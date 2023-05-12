package goaway

import (
	"net/http"
	"os"
	"time"

	"github.com/gorilla/context"
)

type GoAway struct {
	GoAwayFunctions
	GoAwayConfig
}

type GoAwayFunctions struct {
	UserFromCredentials             func(string, string) (interface{}, error)
	UserFromRefreshToken            func(string) (interface{}, error)
	NewPayloadFromUser              func(interface{}) (interface{}, error)
	NewRefreshTokenFromUser         func(interface{}) (string, error)
	ValidateRefreshTokenFromPayload func(string, interface{}) error
	RevokeRefreshToken              func(string) error
}

type GoAwayConfig struct {
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	EnvAccessTokenPrivateKey string
	EnvAccessTokenPublicKey  string
	CookieAccessToken        string
	CookieRefreshToken       string
	ContextPayload           string
}

var DefaultGoAwayConfig = GoAwayConfig{
	AccessTokenTTL:           15 * time.Minute,
	RefreshTokenTTL:          24 * time.Hour,
	EnvAccessTokenPrivateKey: "ACCESS_TOKEN_PRIVATE_KEY",
	EnvAccessTokenPublicKey:  "ACCESS_TOKEN_PUBLIC_KEY",
	CookieAccessToken:        "access_token",
	CookieRefreshToken:       "refresh_token",
	ContextPayload:           "payload",
}

// Returns a GoAway object
func NewGoAway(
	functions GoAwayFunctions,
	config ...GoAwayConfig) GoAway {
	return GoAway{
		GoAwayFunctions: functions,
		GoAwayConfig:    DefaultGoAwayConfig,
	}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (g *GoAway) Login(w http.ResponseWriter, r *http.Request) {
	// Only allows POST request otherwise responds with an error 405
	if r.Method != "POST" {
		JSONResponse(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed(r.Method))
		return
	}

	// Parses the request body
	var req LoginRequest
	if err := MustParseRequest(r.Body, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, ErrInvalidRequestBody(err))
		return
	}
	defer r.Body.Close()

	// Gets the user payload if the credentials are valid
	user, err := g.UserFromCredentials(req.Username, req.Password)
	if err != nil {
		JSONResponse(w, http.StatusUnauthorized, ErrInvalidCredentials)
		return
	}

	// Generates a new token pair from the given payload
	now := time.Now()
	accessToken, refreshToken, err := g.generateTokenPair(user, now)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, ErrFailGenerateTokenPair(err))
		return
	}

	// Generates cookies for access and refresh tokens and set them in the request
	http.SetCookie(w, &http.Cookie{
		Name:     g.CookieAccessToken,
		Value:    accessToken,
		Expires:  now.Add(g.AccessTokenTTL),
		HttpOnly: true,
		Path:     "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:     g.CookieRefreshToken,
		Value:    refreshToken,
		Expires:  now.Add(g.RefreshTokenTTL),
		HttpOnly: true,
		Path:     "/",
	})

	JSONResponse(w, http.StatusOK, Response{
		Status:       "success",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func (g *GoAway) Logout(w http.ResponseWriter, r *http.Request) {
	// Only allows POST request otherwise responds with an error 405
	if r.Method != "POST" {
		JSONResponse(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed(r.Method))
		return
	}

	// Gets the refresh token from the cookie and deletes it from token store
	refreshTokenCookie, err := r.Cookie(g.CookieRefreshToken)
	if err != nil {
		JSONResponse(w, http.StatusBadRequest, ErrCookieIsMissing(err))
		return
	}
	if err := g.RevokeRefreshToken(refreshTokenCookie.Value); err != nil {
		JSONResponse(w, http.StatusInternalServerError, ErrFailRevokeRefreshToken(err))
		return
	}

	// Clears the cookies containing the access and refresh tokens
	http.SetCookie(w, &http.Cookie{Name: g.CookieAccessToken, Expires: time.Now()})
	http.SetCookie(w, &http.Cookie{Name: g.CookieRefreshToken, Expires: time.Now()})

	JSONResponse(w, http.StatusOK, ResSuccessfulLogout)
}

func (g *GoAway) Refresh(w http.ResponseWriter, r *http.Request) {
	// Only allows POST request otherwise responds with an error 405
	if r.Method != "POST" {
		JSONResponse(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed(r.Method))
		return
	}

	// Gets the refresh token from the cookie and first gets and the deletes it from token store
	refreshTokenCookie, err := r.Cookie(g.CookieRefreshToken)
	if err != nil {
		JSONResponse(w, http.StatusBadRequest, ErrCookieIsMissing(err))
		return
	}

	// Rotates the tokens and generates a new pair
	user, err := g.UserFromRefreshToken(refreshTokenCookie.Value)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, ErrInvalidRefreshToken(err))
		return
	}
	if err := g.RevokeRefreshToken(refreshTokenCookie.Value); err != nil {
		JSONResponse(w, http.StatusInternalServerError, ErrFailRevokeRefreshToken(err))
		return
	}
	createdAt := time.Now()
	accessToken, refreshToken, err := g.generateTokenPair(user, createdAt)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, ErrFailGenerateTokenPair(err))
		return
	}

	// Generates cookies for the token pair and set them in the request
	http.SetCookie(w, &http.Cookie{
		Name:     g.CookieAccessToken,
		Value:    accessToken,
		Expires:  createdAt.Add(g.AccessTokenTTL),
		HttpOnly: true,
		Path:     "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:     g.CookieRefreshToken,
		Value:    refreshToken,
		Expires:  createdAt.Add(g.RefreshTokenTTL),
		HttpOnly: true,
		Path:     "/",
	})

	JSONResponse(w, http.StatusOK, Response{
		Status:       "success",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// Returns a http Handler that takes the access token from the requests cookie and validates it.
// The extracted paylod of the access token is attached to the context.
func (g *GoAway) ValidateAccessToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Gets the tokens from the cookies
		accessTokenCookie, err := r.Cookie(g.CookieAccessToken)
		if err != nil {
			JSONResponse(w, http.StatusUnauthorized, ErrCookieIsMissing(err))
			return
		}
		refreshTokenCookie, err := r.Cookie(g.CookieRefreshToken)
		if err != nil {
			JSONResponse(w, http.StatusUnauthorized, ErrCookieIsMissing(err))
		}

		payload, err := ValidateAccessToken(
			accessTokenCookie.Value,
			os.Getenv(g.EnvAccessTokenPublicKey))
		if err != nil {
			JSONResponse(w, http.StatusUnauthorized, ErrInvalidAccessToken(err))
			return
		}

		// Checks if the refresh token matches the access token
		if err := g.ValidateRefreshTokenFromPayload(refreshTokenCookie.Value, payload); err != nil {
			JSONResponse(w, http.StatusUnauthorized, ErrInvalidRefreshToken(err))
			return
		}

		// Attaches the payload to the requests context and serves the next handler
		context.Set(r, g.ContextPayload, payload)
		next.ServeHTTP(w, r)
	})

}

// Returns a freshly generated pair of accessToken and refreshToken from the given user and synced timestamp.
func (g *GoAway) generateTokenPair(user interface{}, createdAt time.Time) (string, string, error) {
	payload, err := g.NewPayloadFromUser(user)
	if err != nil {
		return "", "", err
	}
	accessToken, err := GenerateAccessToken(
		createdAt.Add(g.AccessTokenTTL),
		payload,
		os.Getenv(g.EnvAccessTokenPrivateKey))
	if err != nil {
		return "", "", err
	}
	refreshToken, err := g.NewRefreshTokenFromUser(user)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}
