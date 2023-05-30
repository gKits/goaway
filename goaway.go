package goaway

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/context"
)

type GoAway[U, P interface{}] struct {
	GoAwayFunctions[U, P]
	GoAwayConfig
}

type GoAwayFunctions[U, P interface{}] struct {
	UserFromCreds   func(string, string) (U, error) // Finds the user of the given username and returns it if the password matches
	UserFromRT      func(string) (U, error)         // Finds the corresponding user from the given RT payload and returns it
	NewPayload      func(U) (P, error)              // Generates an AT payload from the given user and returns it
	StoreRT         func(U) (string, error)         // Stores the RT payload and returns its unique ID
	RevokeRT        func(string) error              // Deletes the RT with the given ID
	BlacklistAT     func(string) error              // Stores the given AT in the blacklist
	RTIsRevoked     func(string) bool               // Checks weither the RT with the given ID is revoked
	ATIsBlacklisted func(string) bool               // Checks weither the AT is blacklisted
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type GoAwayConfig struct {
	AccessTokenTTL            time.Duration
	RefreshTokenTTL           time.Duration
	EnvAccessTokenPrivateKey  string
	EnvAccessTokenPublicKey   string
	EnvRefreshTokenPrivateKey string
	EnvRefreshTokenPublicKey  string
	CookieAccessToken         string
	CookieRefreshToken        string
	ContextPayload            string
	CookieDomain              string
	CookiePath                string
	CookieHttpOnly            bool
	CookieSecure              bool
}

var DefaultGoAwayConfig = GoAwayConfig{
	AccessTokenTTL:            15 * time.Minute,
	RefreshTokenTTL:           24 * time.Hour,
	EnvAccessTokenPrivateKey:  "ACCESS_TOKEN_PRIVATE_KEY",
	EnvAccessTokenPublicKey:   "ACCESS_TOKEN_PUBLIC_KEY",
	EnvRefreshTokenPrivateKey: "REFRESH_TOKEN_PRIVATE_KEY",
	EnvRefreshTokenPublicKey:  "REFRESH_TOKEN_PUBLIC_KEY",
	CookieAccessToken:         "access_token",
	CookieRefreshToken:        "refresh_token",
	ContextPayload:            "payload",
	CookieDomain:              "",
	CookiePath:                "/",
	CookieHttpOnly:            true,
	CookieSecure:              false,
}

// Create a new GoAway object with the given User and Payload type and the functions.
func NewGoAway[U, P interface{}](
	UserFromCreds func(string, string) (U, error),
	UserFromRT func(string) (U, error),
	NewPayload func(U) (P, error),
	StoreRT func(U) (string, error),
	RevokeRT func(string) error,
	BlacklistAT func(string) error,
	RTIsRevoked func(string) bool,
	ATIsBlacklisted func(string) bool,
	configs ...GoAwayConfig) (*GoAway[U, P], error) {
	var config *GoAwayConfig
	if len(configs) > 1 {
		return nil, fmt.Errorf("GoAway: cannot use multiple configurations")
	} else if len(configs) == 1 {
		var err error
		config, err = Merge(configs[0], DefaultGoAwayConfig)
		if err != nil {
			return nil, fmt.Errorf("GoAway: could not merge config with default config: %e", err)
		}
	} else {
		config = &DefaultGoAwayConfig
	}
	return &GoAway[U, P]{
		GoAwayFunctions: GoAwayFunctions[U, P]{
			UserFromCreds:   UserFromCreds,
			UserFromRT:      UserFromRT,
			NewPayload:      NewPayload,
			StoreRT:         StoreRT,
			RevokeRT:        RevokeRT,
			BlacklistAT:     BlacklistAT,
			RTIsRevoked:     RTIsRevoked,
			ATIsBlacklisted: ATIsBlacklisted,
		},
		GoAwayConfig: *config,
	}, nil
}

// Login handler that takes username and password from the request body and generates a token pair if the credentials are valid.
func (g *GoAway[U, P]) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		JSONResponse(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed(r.Method))
		return
	}

	var req LoginRequest
	if err := MustParseRequest(r.Body, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, ErrInvalidRequestBody(err))
		return
	}
	defer r.Body.Close()

	user, err := g.UserFromCreds(req.Username, req.Password)
	if err != nil {
		JSONResponse(w, http.StatusUnauthorized, ErrInvalidCredentials)
		return
	}

	now := time.Now()
	accessToken, refreshToken, err := g.generateTokenPair(user, now)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, ErrFailGenerateTokenPair(err))
		return
	}

	http.SetCookie(w, NewCookie(g.CookieAccessToken, accessToken, g.CookieDomain, g.CookiePath, now.Add(g.AccessTokenTTL), g.CookieHttpOnly, g.CookieSecure))
	http.SetCookie(w, NewCookie(g.CookieRefreshToken, refreshToken, g.CookieDomain, g.CookiePath, now.Add(g.RefreshTokenTTL), g.CookieHttpOnly, g.CookieSecure))

	JSONResponse(w, http.StatusOK, Response{
		Status:      "success",
		AccessToken: accessToken,
	})
}

// Logout handler that revokes the refresh token and removes the access and refresh token from the cookie.
func (g *GoAway[U, P]) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		JSONResponse(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed(r.Method))
		return
	}

	rtCookie, err := r.Cookie(g.CookieRefreshToken)
	if err != nil {
		JSONResponse(w, http.StatusBadRequest, ErrCookieIsMissing(err))
		return
	}

	accessToken, err := AccessTokenFromHeaderOrCookie(r, "Authorization", g.CookieAccessToken)
	if err != nil {
		JSONResponse(w, http.StatusBadRequest, nil)
		return
	}

	r.Header.Set("Authorization", "")
	http.SetCookie(w, NewCookie(g.CookieAccessToken, "", g.CookieDomain, g.CookiePath, time.Now(), g.CookieHttpOnly, g.CookieSecure))
	http.SetCookie(w, NewCookie(g.CookieRefreshToken, "", g.CookieDomain, g.CookiePath, time.Now(), g.CookieHttpOnly, g.CookieSecure))

	rtClaims, err := ValidateJWT[string](rtCookie.Value, g.EnvRefreshTokenPublicKey)
	if err != nil {
		JSONResponse(w, http.StatusUnauthorized, nil)
		return
	}

	if err := g.RevokeRT(rtClaims.ID); err != nil {
		JSONResponse(w, http.StatusInternalServerError, ErrFailRevokeRefreshToken(err))
		return
	}
	if err := g.BlacklistAT(accessToken); err != nil {
		JSONResponse(w, http.StatusInternalServerError, nil)
		return
	}

	JSONResponse(w, http.StatusOK, ResSuccessfulLogout)
}

// Refresh handler revokes the old refresh token and generates a new token pair from the old pair.
func (g *GoAway[U, P]) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		JSONResponse(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed(r.Method))
		return
	}

	refreshTokenCookie, err := r.Cookie(g.CookieRefreshToken)
	if err != nil {
		JSONResponse(w, http.StatusBadRequest, ErrCookieIsMissing(err))
		return
	}

	accessToken, err := AccessTokenFromHeaderOrCookie(r, "Authorization", g.CookieAccessToken)
	if err != nil {
		JSONResponse(w, http.StatusBadRequest, nil)
		return
	}

	rtClaims, err := ValidateJWT[string](refreshTokenCookie.Value, os.Getenv(g.EnvRefreshTokenPublicKey))
	if err != nil {
		JSONResponse(w, http.StatusUnauthorized, nil)
		return
	}

	user, err := g.UserFromRT(rtClaims.ID)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, ErrInvalidRefreshToken(err))
		return
	}

	if err := g.RevokeRT(refreshTokenCookie.Value); err != nil {
		JSONResponse(w, http.StatusInternalServerError, ErrFailRevokeRefreshToken(err))
		return
	}

	if err := g.BlacklistAT(accessToken); err != nil {
		JSONResponse(w, http.StatusInternalServerError, nil)
		return
	}

	now := time.Now()

	accessToken, refreshToken, err := g.generateTokenPair(user, now)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, ErrFailGenerateTokenPair(err))
		return
	}

	http.SetCookie(w, NewCookie(g.CookieAccessToken, accessToken, g.CookieDomain, g.CookiePath, now.Add(g.AccessTokenTTL), g.CookieHttpOnly, g.CookieSecure))
	http.SetCookie(w, NewCookie(g.CookieRefreshToken, refreshToken, g.CookieDomain, g.CookiePath, now.Add(g.RefreshTokenTTL), g.CookieHttpOnly, g.CookieSecure))

	JSONResponse(w, http.StatusOK, Response{
		Status:      "success",
		AccessToken: accessToken,
	})
}

// Middleware that validates the access token from the cookie and attaches its paylod to the context.
func (g *GoAway[U, P]) ValidateAccessToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken, err := AccessTokenFromHeaderOrCookie(r, "Authorization", g.CookieAccessToken)
		if err != nil {
			JSONResponse(w, http.StatusUnauthorized, nil)
			return
		}

		claims, err := ValidateJWT[P](
			accessToken,
			os.Getenv(g.EnvAccessTokenPublicKey))
		if err != nil {
			JSONResponse(w, http.StatusUnauthorized, ErrInvalidAccessToken(err))
			return
		}

		context.Set(r, g.ContextPayload, claims.Data)
		next.ServeHTTP(w, r)
	})

}

// Returns a freshly generated pair of accessToken and refreshToken from the given user and synced timestamp.
func (g *GoAway[U, P]) generateTokenPair(user U, now time.Time) (string, string, error) {
	atPayload, err := g.NewPayload(user)
	if err != nil {
		return "", "", err
	}

	refreshTokenID, err := g.StoreRT(user)
	if err != nil {
		return "", "", err
	}

	accessToken, err := GenerateJWT(now, g.AccessTokenTTL, atPayload, os.Getenv(g.EnvAccessTokenPrivateKey))
	if err != nil {
		return "", "", err
	}
	refreshToken, err := GenerateJWT(now, g.RefreshTokenTTL, refreshTokenID, os.Getenv(g.EnvRefreshTokenPrivateKey))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
