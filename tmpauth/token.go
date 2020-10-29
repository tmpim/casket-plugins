package tmpauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type CachedToken struct {
	StateID        string
	UserDescriptor string
	CachedHeaders  map[string]string
	Expiry         time.Time
	UserIDs        []string // IDs that can be used in Config.AllowedUsers from IDFormats
	headersMutex   *sync.RWMutex
}

func (t *Tmpauth) parseAuthJWT(tokenStr string, doNotCache ...bool) (*CachedToken, error) {
	t.DebugLog("parsing auth JWT: " + tokenStr)

	tokenID := sha256.Sum256([]byte(tokenStr))
	t.tokenCacheMutex.Lock()
	if cachedToken, found := t.TokenCache[tokenID]; found {
		t.tokenCacheMutex.Unlock()
		if cachedToken.Expiry.Before(time.Now()) {
			return nil, errors.New("tmpauth: token expired")
		}

		return cachedToken, nil
	}
	t.tokenCacheMutex.Unlock()

	token, err := jwt.Parse(tokenStr, t.VerifyWithPublicKey)
	if err != nil {
		return nil, err
	}

	mapClaims := token.Claims.(jwt.MapClaims)
	if !mapClaims.VerifyAudience(TmpAuthHost+":server:identity:"+t.Config.ClientID, true) {
		return nil, fmt.Errorf("tmpauth: invalid audience: %v", mapClaims["aud"])
	}
	if !mapClaims.VerifyIssuer(TmpAuthHost+":central", true) {
		return nil, fmt.Errorf("tmpauth: issuer invalid, got: %v", mapClaims["iss"])
	}
	if !mapClaims.VerifyExpiresAt(time.Now().Unix(), false) {
		return nil, fmt.Errorf("tmpauth: token expired")
	}

	stateID, ok := mapClaims["stateID"].(string)
	if !ok {
		return nil, fmt.Errorf("tmpauth: state ID missing from claims")
	}

	resp, err := t.HttpClient.Get("https://" + TmpAuthHost + "/whomst/tmpauth?token=" + url.QueryEscape(tokenStr))
	if err != nil {
		return nil, fmt.Errorf("tmpauth: failed to retrieve whomst data: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tmpauth: got non OK response when retrieving token: %v", resp.Status)
	}

	var whomstData interface{}
	err = json.NewDecoder(resp.Body).Decode(&whomstData)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("tmpauth: failed to read whomst response: %w", err)
	}

	var expiry time.Time
	switch exp := mapClaims["exp"].(type) {
	case float64:
		expiry = time.Unix(int64(exp), 0)
	case json.Number:
		v, _ := exp.Int64()
		expiry = time.Unix(int64(v), 0)
	default:
		expiry = time.Now().Add(3650 * 24 * time.Hour)
	}

	// remarshal to ensure that json has no unnecessary whitespace.
	descriptor, err := json.Marshal(&userDescriptor{
		Whomst: whomstData,
		Token:  token.Claims,
	})
	if err != nil {
		return nil, fmt.Errorf("tmpauth: fatal error: failed to marshal user descriptor: %w", err)
	}

	cachedToken := &CachedToken{
		UserDescriptor: string(descriptor),
		CachedHeaders:  make(map[string]string),
		Expiry:         expiry,
		StateID:        stateID,
		headersMutex:   new(sync.RWMutex),
	}

	for _, idFormat := range t.Config.IDFormats {
		cachedToken.UserIDs = append(cachedToken.UserIDs,
			getJSONPathMany(cachedToken.UserDescriptor, idFormat)...)
	}

	if len(doNotCache) == 0 {
		t.tokenCacheMutex.Lock()
		t.TokenCache[tokenID] = cachedToken
		t.tokenCacheMutex.Unlock()
	}

	return cachedToken, nil
}

type userDescriptor struct {
	Whomst interface{} `json:"whomst"`
	Token  jwt.Claims  `json:"token"`
}

func (t *Tmpauth) SetHeaders(token *CachedToken, headers http.Header) error {
	var headersToCache [][2]string

	token.headersMutex.RLock()
	for headerName, headerOption := range t.Config.Headers {
		if val, found := token.CachedHeaders[headerOption.Format]; found {
			headers.Set(headerName, val)
		} else {
			value, err := headerOption.Evaluate(token.UserDescriptor)
			if err != nil {
				t.DebugLog("failed to evaluate header option for header %q with format %q on claim: %v",
					headerName, headerOption.Format, token.UserDescriptor)

				return fmt.Errorf("tmpauth: failed to evaluate required user claims field, turn on debugging for more details")
			}

			headers.Set(headerName, value)
			headersToCache = append(headersToCache, [2]string{headerOption.Format, value})
		}
	}
	token.headersMutex.RUnlock()

	if len(headersToCache) > 0 {
		token.headersMutex.Lock()
		for _, entry := range headersToCache {
			token.CachedHeaders[entry[0]] = entry[1]
		}
		token.headersMutex.Unlock()
	}

	return nil
}

func generateTokenID() string {
	buf := make([]byte, 16)
	n, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	if n != 16 {
		panic("tmpauth: generateTokenID: crypto/rand has failed")
	}

	return hex.EncodeToString(buf)
}

type stateClaims struct {
	CallbackURL string `json:"callbackURL"`
	clientID    string
	jwt.StandardClaims
}

func (c *stateClaims) Valid() error {
	if !c.VerifyIssuer(TmpAuthHost+":server:"+c.clientID, true) {
		return fmt.Errorf("tmpauth: issuer invalid, got: %v\n", c.Issuer)
	}
	if !c.VerifyIssuedAt(time.Now().Unix(), true) || !c.VerifyExpiresAt(time.Now().Unix(), true) ||
		!c.VerifyNotBefore(time.Now().Unix(), true) {
		return fmt.Errorf("tmpauth: token expired")
	}

	return nil
}
