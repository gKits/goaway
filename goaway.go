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
	UserFromCredentials             func(string, string) (U, error)
	UserFromRefreshToken            func(string) (U, error)
	NewPayloadFromUser              func(U) (P, error)
	NewRefreshTokenFromUser         func(U) (string, error)
	ValidateRefreshTokenFromPayload func(string, P) error
	RevokeRefreshToken              func(string) error
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type GoAwayConfig struct {
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	EnvAccessTokenPrivateKey string
	EnvAccessTokenPublicKey  string
	CookieAccessToken        string
	CookieRefreshToken       string
	ContextPayload           string
	CookieDomain             string
	CookiePath               string
	CookieHttpOnly           bool
	CookieSecure             bool
}

var DefaultGoAwayConfig = GoAwayConfig{
	AccessTokenTTL:           15 * time.Minute,
	RefreshTokenTTL:          24 * time.Hour,
	EnvAccessTokenPrivateKey: "ACCESS_TOKEN_PRIVATE_KEY",
	EnvAccessTokenPublicKey:  "ACCESS_TOKEN_PUBLIC_KEY",
	CookieAccessToken:        "access_token",
	CookieRefreshToken:       "refresh_token",
	ContextPayload:           "payload",
	CookieDomain:             "",
	CookiePath:               "/",
	CookieHttpOnly:           true,
	CookieSecure:             false,
}

// Create a new GoAway object with the given User and Payload type and the functions:
//
//	UfC: UserFromCredentials: returns the user if username and password are valid
//	UfRT: UserFromRefreshToken: returns the user by checking the refresh tokens owner
//	NPfU: NewPayloadFromuser: returns a new payload by generating it from the users data
//	NRTfU: NewRefreshTokenFromUser: generates a new refresh token from the users data and returns the token string
//	VRTfP: ValidateRefreshTokenFromPayload: compares the attached data of the refresh token to the payload
//	RRT: RevokeRefreshToken: revokes the refresh token
func NewGoAway[U, P interface{}](
	UfC func(string, string) (U, error),
	UfRT func(string) (U, error),
	NPfU func(U) (P, error),
	NRTfU func(U) (string, error),
	VRTfP func(string, P) error,
	RRT func(string) error,
	configs ...GoAwayConfig,
) (*GoAway[U, P], error) {
	var config *GoAwayConfig
	if len(configs) > 1 {
		return nil, fmt.Errorf("GoAway: cannot use multiple configurations")
	} else if len(configs) == 1 {
		var err error
		config, err = Merge(configs[0], DefaultGoAwayConfig)
		if err != nil {
			return nil, fmt.Errorf("GoAway: could not merge config with default config: %s", err.Error())
		}
	} else {
		config = &DefaultGoAwayConfig
	}
	return &GoAway[U, P]{
		GoAwayFunctions: GoAwayFunctions[U, P]{
			UserFromCredentials:             UfC,
			UserFromRefreshToken:            UfRT,
			NewPayloadFromUser:              NPfU,
			NewRefreshTokenFromUser:         NRTfU,
			ValidateRefreshTokenFromPayload: VRTfP,
			RevokeRefreshToken:              RRT,
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

	user, err := g.UserFromCredentials(req.Username, req.Password)
	if err != nil {
		JSONResponse(w, http.StatusUnauthorized, ErrInvalidCredentials)
		return
	}

	createdAt := time.Now()
	accessToken, refreshToken, err := g.generateTokenPair(user, createdAt)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, ErrFailGenerateTokenPair(err))
		return
	}

	http.SetCookie(w, NewCookie(g.CookieAccessToken, accessToken, g.CookieDomain, g.CookiePath, createdAt.Add(g.AccessTokenTTL), g.CookieHttpOnly, g.CookieSecure))
	http.SetCookie(w, NewCookie(g.CookieRefreshToken, refreshToken, g.CookieDomain, g.CookiePath, createdAt.Add(g.RefreshTokenTTL), g.CookieHttpOnly, g.CookieSecure))

	JSONResponse(w, http.StatusOK, Response{
		Status:       "success",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// Logout handler that revokes the refresh token and removes the access and refresh token from the cookie.
func (g *GoAway[U, P]) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		JSONResponse(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed(r.Method))
		return
	}

	refreshTokenCookie, err := r.Cookie(g.CookieRefreshToken)
	if err != nil {
		JSONResponse(w, http.StatusBadRequest, ErrCookieIsMissing(err))
		return
	}
	if err := g.RevokeRefreshToken(refreshTokenCookie.Value); err != nil {
		JSONResponse(w, http.StatusInternalServerError, ErrFailRevokeRefreshToken(err))
		return
	}

	http.SetCookie(w, NewCookie(g.CookieAccessToken, "", g.CookieDomain, g.CookiePath, time.Now(), g.CookieHttpOnly, g.CookieSecure))
	http.SetCookie(w, NewCookie(g.CookieRefreshToken, "", g.CookieDomain, g.CookiePath, time.Now(), g.CookieHttpOnly, g.CookieSecure))

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

	http.SetCookie(w, NewCookie(g.CookieAccessToken, accessToken, g.CookieDomain, g.CookiePath, createdAt.Add(g.AccessTokenTTL), g.CookieHttpOnly, g.CookieSecure))
	http.SetCookie(w, NewCookie(g.CookieRefreshToken, refreshToken, g.CookieDomain, g.CookiePath, createdAt.Add(g.RefreshTokenTTL), g.CookieHttpOnly, g.CookieSecure))

	JSONResponse(w, http.StatusOK, Response{
		Status:       "success",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// Middleware that validates the access token from the cookie and attaches its paylod to the context.
func (g *GoAway[U, P]) ValidateAccessToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessTokenCookie, err := r.Cookie(g.CookieAccessToken)
		if err != nil {
			JSONResponse(w, http.StatusUnauthorized, ErrCookieIsMissing(err))
			return
		}
		refreshTokenCookie, err := r.Cookie(g.CookieRefreshToken)
		if err != nil {
			JSONResponse(w, http.StatusUnauthorized, ErrCookieIsMissing(err))
		}

		claims, err := ValidateAccessToken[P](
			accessTokenCookie.Value,
			os.Getenv(g.EnvAccessTokenPublicKey))
		if err != nil {
			JSONResponse(w, http.StatusUnauthorized, ErrInvalidAccessToken(err))
			return
		}

		if err := g.ValidateRefreshTokenFromPayload(refreshTokenCookie.Value, claims.Data); err != nil {
			JSONResponse(w, http.StatusUnauthorized, ErrInvalidRefreshToken(err))
			return
		}

		context.Set(r, g.ContextPayload, claims.Data)
		next.ServeHTTP(w, r)
	})

}

// Returns a freshly generated pair of accessToken and refreshToken from the given user and synced timestamp.
func (g *GoAway[U, P]) generateTokenPair(user U, createdAt time.Time) (string, string, error) {
	payload, err := g.NewPayloadFromUser(user)
	if err != nil {
		return "", "", err
	}
	// TODO: Generate a unique identifier for the token pair
	accessToken, err := GenerateAccessToken(
		createdAt.Add(g.AccessTokenTTL),
		payload,
		"",
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
