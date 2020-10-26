package tmpauth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/tidwall/gjson"
	"github.com/tmpim/casket/caskethttp/httpserver"
)

type CachedToken struct {
	ClaimsString  string
	CachedHeaders map[string]string
	Expiry        time.Time
	UserIDs       []string // IDs that can be used in Config.AllowedUsers from IDFormats
	headersMutex  *sync.RWMutex
}

func (t *Tmpauth) SetHeaders(token *CachedToken, headers http.Header) error {
	var headersToCache [][2]string

	token.headersMutex.RLock()
	for headerName, headerOption := range t.Config.Headers {
		if val, found := token.CachedHeaders[headerOption.Format]; found {
			headers.Set(headerName, val)
		} else {
			value, err := headerOption.Evaluate(token.ClaimsString)
			if err != nil {
				t.DebugLog("failed to evaluate header option for header %q with format %q on claim: %v",
					headerName, headerOption.Format, token.ClaimsString)

				return fmt.Errorf("tmpauth: failed to evaluate required user claims field, turn on debugging for more details")
			}

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

type Tmpauth struct {
	Next            httpserver.Handler
	Config          *Config
	Logger          *log.Logger
	TokenCache      map[[32]byte]*CachedToken
	HttpClient      *http.Client
	tokenCacheMutex *sync.Mutex
}

var errAuthFail = errors.New("chuieauth: authentication failure")

func (t *Tmpauth) DebugLog(fmtString string, args ...interface{}) {
	if !t.Config.Debug {
		return
	}

	t.Logger.Output(2, fmt.Sprintf(fmtString, args...))
}

func (t *Tmpauth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if strings.HasPrefix(r.URL.Path, "/.well-known/tmpauth/") {
		switch strings.TrimPrefix(r.URL.Path, "/.well-known/tmpauth/") {
		case "callback":
			return t.authCallback(w, r)
		case "ping":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"tmpauth":  true,
				"clientID": t.Config.ClientID,
			})
			return 0, nil
		default:
			return 400, fmt.Errorf("tmpauth: no such path")
		}
	}

	// determine if auth is required
	authRequired := true

	// If the URL path is weird, it signals a possible attack attempt.
	// always require authentication in such a condition.
	if path.Clean(r.URL.Path) == r.URL.Path {
		if len(t.Config.Except) > 0 {
			for _, exempt := range t.Config.Except {
				if strings.HasPrefix(r.URL.Path, exempt) {
					authRequired = false
					break
				}
			}
		} else if len(t.Config.Include) > 0 {
			found := false
			for _, included := range t.Config.Include {
				if strings.HasPrefix(r.URL.Path, included) {
					found = true
					break
				}
			}
			if !found {
				authRequired = false
			}
		}
	}

	t.DebugLog("auth requirement for %q: %v", r.URL.Path, authRequired)

	cachedToken, err := t.authFromCookie(r)
	if err != nil {
		t.DebugLog("failed to get JWT token: %v", err)

		if _, err := r.Cookie(t.CookieName()); err != http.ErrNoCookie {
			t.DebugLog("cookie exists and deemed to be invalid, requesting client to delete cookie")

			http.SetCookie(w, &http.Cookie{
				Name:     t.CookieName(),
				Value:    "",
				MaxAge:   -1,
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
		}

		if authRequired {
			return t.startAuth(w, r)
		}
	}

	if cachedToken != nil {

	}

	// return t.authenticateSessionAndReturn(w, r, pathMatch.authId)
	return 0, nil
}

func (t *Tmpauth) CookieName() string {
	return "__Host-tmpauth_" + t.Config.ClientID
}

type metatokenClaims struct {
	RedirectURI string `json:"redirectURI"`
	TokenID     string `json:"tokenID"`
	clientID    string `json:"-"`
	jwt.StandardClaims
}

func (c *metatokenClaims) Valid() error {
	if !c.VerifyAudience(TmpAuthEndpoint+":server:metatoken:"+c.clientID, true) {
		return fmt.Errorf("tmpauth: audience invalid, got: %v", c.Audience)
	}

	if !c.VerifyIssuer(TmpAuthEndpoint+":central", true) {
		return fmt.Errorf("tmpauth: issuer invalid, got: %v", c.Issuer)
	}

	if !c.VerifyExpiresAt(time.Now().Unix(), true) || !c.VerifyNotBefore(time.Now().Unix(), false) {
		return fmt.Errorf("tmpauth: token has expired")
	}

	return nil
}

func (t *Tmpauth) authCallback(w http.ResponseWriter, r *http.Request) (int, error) {
	params := r.URL.Query()

	// We use metatokens in case the primary token is so large that it cannot fit in a URL query parameter.
	// Hence we retrieve the whole token out of band using a token ID.
	metatokenStr := params.Get("metatoken")

	metatoken, err := jwt.ParseWithClaims(metatokenStr, &metatokenClaims{
		clientID: t.Config.ClientID,
	}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("invalid metatoken signing method: %v", token.Header["alg"])
		}

		return t.Config.PublicKey, nil
	})
	if err != nil {
		t.DebugLog("failed to verify callback metatoken: %v", err)
		return 400, fmt.Errorf("tmpauth: failed to verify callback metatoken")
	}

	metaClaims := metatoken.Claims.(*metatokenClaims)

	resp, err := t.HttpClient.Get(TmpAuthEndpoint + "/auth/get-token?id=" + url.QueryEscape(metaClaims.TokenID))
	if err != nil {
		t.DebugLog("failed to retrieve token from central server: %v", err)
		return 500, fmt.Errorf("tmpauth: failed to retrieve token from central server")
	}

	if resp.StatusCode != http.StatusOK {
		t.DebugLog("got non OK response when retrieving token: %v", resp.Status)
		return 400, fmt.Errorf("tmpauth: (probably) invalid token ID")
	}

	tokenData, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.DebugLog("tmpauth: failed to read response from central server: %v", err)
		return 500, fmt.Errorf("tmpauth: failed to read response from central server")
	}

	tokenStr := string(tokenData)
	token, err := t.parseAuthJWT(tokenStr)
	if err != nil {
		t.DebugLog("failed to verify callback token: %v", err)
		return 400, fmt.Errorf("tmpauth: failed to verify callback token")
	}

	t.DebugLog("auth callback successful, setting cookie")

	http.SetCookie(w, &http.Cookie{
		Name:     t.CookieName(),
		Value:    tokenStr,
		Expires:  token.Expiry,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, metaClaims.RedirectURI, http.StatusSeeOther)
	return 0, nil
}

func (t *Tmpauth) startAuth(w http.ResponseWriter, r *http.Request) (int, error) {
	return 0, nil
}

func (t *Tmpauth) parseAuthJWT(tokenStr string) (*CachedToken, error) {
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

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("tmpauth: invalid secret signing method: %v", token.Header["alg"])
		}

		return t.Config.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}

	mapClaims := token.Claims.(jwt.MapClaims)
	if !mapClaims.VerifyAudience(TmpAuthEndpoint+":server:identity:"+t.Config.ClientID, true) {
		return nil, fmt.Errorf("tmpauth: invalid audience: %v", mapClaims["aud"])
	}
	if !mapClaims.VerifyIssuer(TmpAuthEndpoint+":central", true) {
		return nil, fmt.Errorf("tmpauth: issuer invalid, got: %v", mapClaims["iss"])
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

	claims, err := json.Marshal(token.Claims)
	if err != nil {
		return nil, fmt.Errorf("tmpauth: fatal error: failed to marshal claims: %w", err)
	}

	cachedToken := &CachedToken{
		ClaimsString:  string(claims),
		CachedHeaders: make(map[string]string),
		Expiry:        expiry,
		headersMutex:  new(sync.RWMutex),
	}

	for _, idFormat := range t.Config.IDFormats {
		cachedToken.UserIDs = append(cachedToken.UserIDs,
			getJSONPathMany(cachedToken.ClaimsString, idFormat)...)
	}

	t.tokenCacheMutex.Lock()
	t.TokenCache[tokenID] = cachedToken
	t.tokenCacheMutex.Unlock()

	return cachedToken, nil
}

func (t *Tmpauth) authFromCookie(r *http.Request) (*CachedToken, error) {
	cookie, err := r.Cookie(t.CookieName())
	if err != nil {
		return nil, err
	}

	return t.parseAuthJWT(cookie.Value)
}

func getJSONPath(jsonData, path string) string {
	result := gjson.Get(jsonData, path)
	if !result.Exists() {
		return ""
	}

	return result.String()
}

func getJSONPathMany(jsonData, path string) []string {
	var results []string
	result := gjson.Get(jsonData, path)
	for _, val := range result.Array() {
		results = append(results, val.String())
	}

	return results
}

type HeaderOption struct {
	Format   string
	Optional bool
}

func (h *HeaderOption) Evaluate(jsonData string) (string, error) {
	result := getJSONPath(jsonData, h.Format)
	if result == "" && !h.Optional {
		return "", fmt.Errorf("tmpauth: requested header format yielded no results on claim")
	}

	return result, nil
}
