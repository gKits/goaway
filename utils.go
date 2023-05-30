package goaway

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

func NewCookie(name, value, domain, path string, expires time.Time, httpOnly, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   domain,
		Path:     path,
		Expires:  expires,
		HttpOnly: httpOnly,
		Secure:   secure,
	}
}

func JSONResponse(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func MustParseRequest(b io.ReadCloser, v interface{}) error {
	decoder := json.NewDecoder(b)
	decoder.DisallowUnknownFields()
	return decoder.Decode(&v)
}

func AccessTokenFromHeaderOrCookie(r *http.Request, header, cookie string) (string, error) {
	var accessToken string
	accessToken = r.Header.Get(header)
	if accessToken == "" {
		atCookie, err := r.Cookie(cookie)
		if err != nil {
			return "", err
		}
		accessToken = atCookie.Value
	} else {
		accessToken = strings.TrimPrefix(accessToken, "Bearer ")
	}
	return accessToken, nil
}

func Merge[T interface{}](a, b T) (*T, error) {
	byteB, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(byteB, &a); err != nil {
		return nil, err
	}
	return &a, nil
}
