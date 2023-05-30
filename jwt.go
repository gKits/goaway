package goaway

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type GoAwayClaims[P interface{}] struct {
	Data P `json:"data,omitempty"`
	jwt.RegisteredClaims
}

// Returns an jwt that contains the given payload of the specified type.
// It expires at the given expiresAt time and is encoded with RS256 using b64 encoded privateKey.
// The id is used as a unique identifier of the token.
func GenerateJWT[P interface{}](now time.Time, ttl time.Duration, payload P, privateKey string) (string, error) {
	pemKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", err
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(pemKey)
	if err != nil {
		return "", err
	}

	claims := GoAwayClaims[P]{
		Data: payload,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", err
	}

	return token, nil
}

// Returns the claims of the given jwt after decoding using RSA with the b64 encoded publicKey.
// The type of the payload in use has to be specified as a generic type.
func ValidateJWT[P interface{}](token, publicKey string) (*GoAwayClaims[P], error) {
	pemKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(pemKey)
	if err != nil {
		return nil, err
	}

	parsedToken, err := jwt.ParseWithClaims(token, &GoAwayClaims[P]{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", t.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := parsedToken.Claims.(*GoAwayClaims[P])
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
