package goaway

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func GenerateAccessToken(expiresIn time.Time, payload interface{}, privateKey string) (string, error) {
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

	// Create claims with payload that expires in ttl
	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	claims["sub"] = payload
	claims["exp"] = expiresIn.Unix()
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()

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
func ValidateAccessToken(token, publicKey string) (interface{}, error) {
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

	parser := jwt.NewParser(jwt.WithJSONNumber())

	parsedToken, err := parser.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", t.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims["sub"], nil
}
