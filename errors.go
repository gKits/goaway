package goaway

import "fmt"

type Response struct {
	Status       string `json:"status"`
	Message      string `json:"message,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

var (
	ErrInvalidCredentials = Response{Status: "error", Message: "1 or more credentials are invalid"}
	ResSuccessfulLogout   = Response{Status: "success", Message: "successfully logged out"}
)

func ErrInvalidRequestBody(err error) Response {
	return Response{Status: "error", Message: fmt.Sprintf("request body invalid or malformed: %s", err.Error())}
}
func ErrInvalidAccessToken(err error) Response {
	return Response{Status: "error", Message: fmt.Sprintf("access token validation failed: %s", err.Error())}
}
func ErrFailGenerateTokenPair(err error) Response {
	return Response{Status: "error", Message: fmt.Sprintf("failed to generate token pair: %s", err.Error())}
}
func ErrFailTokenRotation(err error) Response {
	return Response{Status: "error", Message: fmt.Sprintf("rotation of refresh token failed: %s", err.Error())}
}
func ErrFailDeleteRefreshToken(err error) Response {
	return Response{Status: "error", Message: fmt.Sprintf("could not delete refresh token: %s", err.Error())}
}
func ErrCookieIsMissing(err error) Response {
	return Response{Status: "error", Message: fmt.Sprintf("cookie is missing from request: %s", err.Error())}
}
func ErrMethodNotAllowed(method string) Response {
	return Response{Status: "error", Message: fmt.Sprintf("method '%s' is not allowed", method)}
}
