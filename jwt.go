package goaway

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type GoAwayClaims[P interface{}] struct {
	Data P `json:"data"`
	jwt.RegisteredClaims
}

func GenerateAccessToken[P interface{}](expiresAt time.Time, payload P, id, privateKey string) (string, error) {
	// Decode B64 encoded private key
	pemKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", err
	}

	// Parse key from decoded PEM
	key, err := jwt.ParseRSAPrivateKeyFromPEM(pemKey)
	if err != nil {
		return "", err
	}

	claims := GoAwayClaims[P]{
		Data: payload,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        id,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	// Generate token and sign it with private key
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", err
	}

	return token, nil
}

// Validates the given token string by parsing it with the given publicKey.
// The extraced claims from the jwt are parsed into the targetClaims.
// Type of the targetClaims has to be specified as a generic
//
// Returns an error if the decoding, parsing or validation fails
func ValidateAccessToken[P interface{}](token, publicKey string) (*GoAwayClaims[P], error) {
	// Decode B64 encoded public key
	pemKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}

	// Parse public key from PEM
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
