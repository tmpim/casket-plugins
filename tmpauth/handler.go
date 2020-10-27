package tmpauth

import (
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

		if statusRequested {
			return t.serveStatus(w, r, nil)
		}

		if authRequired {
			return t.startAuth(w, r)
		}
	}

	if statusRequested {
		return t.serveStatus(w, r, cachedToken)
	}

	// return t.authenticateSessionAndReturn(w, r, pathMatch.authId)
	return 0, nil
}

func (t *Tmpauth) authCallback(w http.ResponseWriter, r *http.Request) (int, error) {
	params := r.URL.Query()

	t.DebugLog("executing authCallback flow")

	// We use metatokens in case the primary token is so large that it cannot fit in a URL query parameter.
	// Hence we retrieve the whole token out of band using a token ID.
	tokenStr := params.Get("token")
	stateStr := params.Get("state")

	state, err := jwt.ParseWithClaims(stateStr, &stateClaims{}, t.VerifyWithSecret)
	if err != nil {
		t.DebugLog("failed to verify state token: %v", err)
	}

	claims := state.Claims.(*stateClaims)

	// TODO: MUST add a parameter to parse only, no caching.
	// otherwise it could result in a state check skip!
	token, err := t.parseAuthJWT(tokenStr)
	if err != nil {
		t.DebugLog("failed to verify callback token: %v", err)
		return 400, fmt.Errorf("tmpauth: failed to verify callback token")
	}

	stateCookie, err := r.Cookie(t.StateIDCookieName(token.StateID))
	if err != nil || !isCookieSecure(stateCookie) {
		return 400, fmt.Errorf("tmpauth: failed to verify state ID")
	}

	http.SetCookie(w, &http.Cookie{
		Name:     t.StateIDCookieName(token.StateID),
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	if token.StateID != claims.Id {
		t.DebugLog("failed to verify state ID: token(%v) != state(%v)", token.StateID, claims.Id)
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

	http.Redirect(w, r, claims.RedirectURI, http.StatusSeeOther)
	return 0, nil
}

func (t *Tmpauth) startAuth(w http.ResponseWriter, r *http.Request) (int, error) {
	now := time.Now()
	expiry := time.Now().Add(5 * time.Minute)
	tokenID := generateTokenID()

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &stateClaims{
		RedirectURI: r.URL.RequestURI(),
		StandardClaims: jwt.StandardClaims{
			Id:        tokenID,
			Issuer:    TmpAuthEndpoint + ":server:" + t.Config.ClientID,
			IssuedAt:  now.Unix(),
			NotBefore: now.Unix(),
			ExpiresAt: expiry.Unix(),
		},
	}).SignedString(t.Config.Secret)
	if err != nil {
		t.DebugLog("failed to sign state token: %v", err)
		return 500, errors.New("tmpauth: failed to start authentication")
	}

	// TODO: store redirect URIs somewhere
	// if URI is <= 64 characters, it's OK to store in a cookie.
	// cookie size limit is 4096. server-side storage might _have_ to be used.
	http.SetCookie(w, &http.Cookie{
		Name:     t.StateIDCookieName(tokenID),
		Value:    tokenID,
		Expires:  expiry,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	queryParams := url.Values{
		"state":    []string{token},
		"clientID": []string{t.Config.ClientID},
	}

	http.Redirect(w, r, TmpAuthEndpoint+"/auth/casket/login?"+queryParams.Encode(), http.StatusSeeOther)

	return 0, nil
}

func (t *Tmpauth) authFromCookie(r *http.Request) (*CachedToken, error) {
	cookie, err := r.Cookie(t.CookieName())
	if err != nil {
		return nil, err
	}

	if !isCookieSecure(cookie) {
		return nil, errors.New("tmpauth: auth cookie is insecure")
	}

	return t.parseAuthJWT(cookie.Value)
}
