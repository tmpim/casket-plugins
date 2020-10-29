package tmpauth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type StatusResponse struct {
	Tmpauth        bool            `json:"tmpauth"`
	ClientID       string          `json:"clientID"`
	IsLoggedIn     bool            `json:"isLoggedIn"`
	UserDescriptor json.RawMessage `json:"loggedInUser,omitempty"`
}

func (t *Tmpauth) serveStatus(w http.ResponseWriter, r *http.Request, token *CachedToken) (int, error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := &StatusResponse{
		Tmpauth:    true,
		ClientID:   t.Config.ClientID,
		IsLoggedIn: token != nil,
	}

	if token != nil {
		resp.UserDescriptor = json.RawMessage(token.UserDescriptor)
	}

	json.NewEncoder(w).Encode(resp)

	return 0, nil
}

func (t *Tmpauth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	statusRequested := false

	if strings.HasPrefix(r.URL.Path, "/.well-known/tmpauth/") {
		switch strings.TrimPrefix(r.URL.Path, "/.well-known/tmpauth/") {
		case "callback":
			return t.authCallback(w, r)
		case "status":
			statusRequested = true
			break
		default:
			return http.StatusBadRequest, fmt.Errorf("tmpauth: no such path")
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
				SameSite: http.SameSiteLaxMode,
			})
		}

		if statusRequested {
			return t.serveStatus(w, r, nil)
		}

		if authRequired {
			return t.startAuth(w, r)
		}
	} else if len(t.Config.Headers) > 0 {
		err := t.SetHeaders(cachedToken, w.Header())
		if err != nil {
			t.DebugLog("failed to set headers: %v", err)
			return http.StatusPreconditionRequired, fmt.Errorf("tmpauth: missing required header value")
		}
	}

	if statusRequested {
		return t.serveStatus(w, r, cachedToken)
	}

	userAuthorized := false
	if len(t.Config.AllowedUsers) > 0 {
		t.DebugLog("checking if user is allowed on allowed users list: %v", cachedToken.UserIDs)
		userIDs := make(map[string]bool)
		for _, userID := range cachedToken.UserIDs {
			userIDs[userID] = true
		}

		for _, allowedUser := range t.Config.AllowedUsers {
			if userIDs[allowedUser] {
				userAuthorized = true
				break
			}
		}
	} else {
		userAuthorized = true
	}

	if !userAuthorized {
		t.DebugLog("user not on allowed users list")
		return http.StatusForbidden, fmt.Errorf("tmpauth: user not in allowed list")
	}

	return t.Next.ServeHTTP(w, r)
}

func (t *Tmpauth) consumeStateID(r *http.Request, w http.ResponseWriter, stateID string) (string, error) {
	t.DebugLog("consuming state ID: %v", stateID)

	defer func() {
		for _, cookie := range r.Cookies() {
			if !strings.HasPrefix(cookie.Name, "__Host-tmpauth-stateid_") {
				continue
			}

			cookie.Value = ""
			cookie.Expires = time.Time{}
			cookie.MaxAge = -1
			cookie.HttpOnly = true
			cookie.Secure = true
			cookie.Path = "/"
			cookie.SameSite = http.SameSiteLaxMode

			http.SetCookie(w, cookie)
		}
	}()

	stateCookie, err := r.Cookie(t.StateIDCookieName(stateID))
	if err != nil {
		return "", fmt.Errorf("tmpauth: state ID cookie not present")
	}

	value, err := url.PathUnescape(stateCookie.Value)
	if err != nil {
		return "", fmt.Errorf("tmpauth: state ID cookie invalid")
	}

	var redirectURI string
	redirectURIRaw, found := t.stateIDCache.Get(stateID)
	if found {
		t.stateIDCache.Delete(stateID)
		redirectURI = redirectURIRaw.(string)
	}

	if value == "ok" {
		if !found {
			return "", nil
		}

		return redirectURI, nil
	} else if value[0] == '/' {
		if !found || redirectURI == value {
			return value, nil
		}

		return "", fmt.Errorf("tmpauth: state ID cookie mis-match")
	}

	return "", fmt.Errorf("tmpauth: state ID cookie invalid")
}

var ErrInvalidCallbackToken = fmt.Errorf("tmpauth: failed to verify callback token")

func (t *Tmpauth) authCallback(w http.ResponseWriter, r *http.Request) (int, error) {
	params := r.URL.Query()

	t.DebugLog("executing authCallback flow")

	// We use metatokens in case the primary token is so large that it cannot fit in a URL query parameter.
	// Hence we retrieve the whole token out of band using a token ID.
	tokenStr := params.Get("token")
	stateStr := params.Get("state")

	state, err := jwt.ParseWithClaims(stateStr, &stateClaims{
		clientID: t.Config.ClientID,
	}, t.VerifyWithSecret)
	if err != nil {
		t.DebugLog("failed to verify state token: %v", err)
		return http.StatusBadRequest, ErrInvalidCallbackToken
	}

	claims := state.Claims.(*stateClaims)

	redirectURI, err := t.consumeStateID(r, w, claims.Id)
	if err != nil {
		t.DebugLog("failed to verify state ID against session: %v", err)
		return http.StatusBadRequest, ErrInvalidCallbackToken
	}

	if params.Get("error") == "cancelled" {
		w.Header().Set("WWW-Authenticate", "tmpauth")
		return http.StatusUnauthorized, fmt.Errorf("tmpauth: auth flow cancelled")
	}

	token, err := t.parseAuthJWT(tokenStr)
	if err != nil {
		t.DebugLog("failed to verify callback token: %v", err)
		return http.StatusBadRequest, ErrInvalidCallbackToken
	}

	if token.StateID != claims.Id {
		t.DebugLog("failed to verify state ID: token(%v) != state(%v)", token.StateID, claims.Id)
		return http.StatusBadRequest, ErrInvalidCallbackToken
	}

	expires := token.Expiry.Unix()
	if expires < 60*60*24*366 {
		expires = 0
	}

	wToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &wrappedToken{
		Token: tokenStr,
		StandardClaims: jwt.StandardClaims{
			Audience:  TmpAuthHost + ":server:user_cookie:" + t.Config.ClientID,
			Issuer:    TmpAuthHost + ":server:" + t.Config.ClientID,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: expires,
		},
	}).SignedString(t.Config.Secret)
	if err != nil {
		t.DebugLog("failed to sign wrapped token: %v", err)
		return http.StatusInternalServerError, fmt.Errorf("tmpauth: failed to sign wrapped token")
	}

	// token validated, can cache now
	tokenID := sha256.Sum256([]byte(wToken))
	t.tokenCacheMutex.Lock()
	t.TokenCache[tokenID] = token
	t.tokenCacheMutex.Unlock()

	t.DebugLog("auth callback successful, setting cookie")

	http.SetCookie(w, &http.Cookie{
		Name:     t.CookieName(),
		Value:    wToken,
		Expires:  token.Expiry,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	if redirectURI == "" {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`you have been successfully authenticated, however we could ` +
			`not tell what the original page was that you were trying to visit.` + "\n" +
			`please try re-visiting the page you were trying to visit again`))
		return 0, nil
	}

	http.Redirect(w, r, redirectURI, http.StatusSeeOther)
	return 0, nil
}

func (t *Tmpauth) startAuth(w http.ResponseWriter, r *http.Request) (int, error) {
	now := time.Now()
	expiry := time.Now().Add(5 * time.Minute)
	tokenID := generateTokenID()

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &stateClaims{
		CallbackURL: "https://" + r.Host + "/.well-known/tmpauth/callback",
		StandardClaims: jwt.StandardClaims{
			Id:        tokenID,
			Issuer:    TmpAuthHost + ":server:" + t.Config.ClientID,
			Audience:  TmpAuthHost + ":central:state",
			IssuedAt:  now.Unix(),
			NotBefore: now.Unix(),
			ExpiresAt: expiry.Unix(),
		},
	}).SignedString(t.Config.Secret)
	if err != nil {
		t.DebugLog("failed to sign state token: %v", err)
		return http.StatusInternalServerError, errors.New("tmpauth: failed to start authentication")
	}

	requestURI := r.URL.RequestURI()

	t.stateIDCache.SetDefault(tokenID, requestURI)

	// store request URIs in cookies sometimes in case this is a distributed
	// casket instance or something and it'll still work in most cases
	if len(requestURI) <= 128 {
		http.SetCookie(w, &http.Cookie{
			Name:     t.StateIDCookieName(tokenID),
			Value:    requestURI,
			Expires:  expiry,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	} else {
		http.SetCookie(w, &http.Cookie{
			Name:     t.StateIDCookieName(tokenID),
			Value:    "ok",
			Expires:  expiry,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	queryParams := url.Values{
		"state":     []string{token},
		"client_id": []string{t.Config.ClientID},
		"method":    []string{"tmpauth"},
	}

	http.Redirect(w, r, "https://"+TmpAuthHost+"/auth?"+queryParams.Encode(), http.StatusSeeOther)

	return 0, nil
}

func (t *Tmpauth) authFromCookie(r *http.Request) (*CachedToken, error) {
	cookie, err := r.Cookie(t.CookieName())
	if err != nil {
		return nil, err
	}

	return t.parseWrappedAuthJWT(cookie.Value)
}
