package goaway

import (
	"encoding/json"
	"io"
	"net/http"
	"time"
)

func NewCookie(name, value, domain, path string, expires time.Time, secure, httpOnly bool) http.Cookie {
	return http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   domain,
		Path:     path,
		Expires:  expires,
		Secure:   secure,
		HttpOnly: httpOnly,
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
