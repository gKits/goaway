package main

import (
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/goaway-auth/goaway"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/segmentio/ksuid"
)

type User struct {
	Id       int    `json:"userid"`
	Username string `json:"username"`
	Password string `json:"-"`
}

type Payload struct {
	Id       int    `json:"userid"`
	Username string `json:"username"`
}

var users = []User{
	{
		Id:       0,
		Username: "user1",
		Password: "password1",
	},
	{
		Id:       1,
		Username: "user2",
		Password: "password2",
	},
	{
		Id:       2,
		Username: "user3",
		Password: "password3",
	},
}

var refreshTokenStore map[string]int = make(map[string]int)

func init() {
	path, err := filepath.Abs("./example.env")
	if err != nil {
		log.Fatalf("filepath does not exist: %s", err.Error())
	}
	log.Printf("loading .env file at '%s'\n", path)
	if err := godotenv.Load(path); err != nil {
		log.Fatal("could not load env")
	}
	log.Println("successfully loaded .env")
}

func main() {
	gw, err := goaway.NewGoAway(
		UserFromCredentials,
		UserFromRefreshToken,
		NewPayloadFromUser,
		NewRefreshTokenFromUser,
		ValidateRefreshTokenFromPayload,
		RevokeRefreshToken,
	)
	if err != nil {
		log.Fatalf("Could not create GoAway object: %s", err.Error())
	}

	r := mux.NewRouter()
	protected := r.PathPrefix("/protected").Subrouter()
	protected.Use(gw.ValidateAccessToken)
	protected.HandleFunc("/test", testHandler)

	r.HandleFunc("/login", gw.Login)
	r.HandleFunc("/logout", gw.Logout)
	r.HandleFunc("/refresh", gw.Refresh)

	srv := http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:5000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}

func testHandler(w http.ResponseWriter, r *http.Request) { goaway.JSONResponse(w, 200, "test") }

func UserFromCredentials(username, password string) (User, error) {
	for _, u := range users {
		if u.Username == username {
			if u.Password == password {
				return u, nil
			}
			return User{}, fmt.Errorf("wrong password")
		}
	}
	return User{}, fmt.Errorf("user '%s' not found", username)
}

func UserFromRefreshToken(refreshToken string) (User, error) {
	id, ok := refreshTokenStore[refreshToken]
	if !ok {
		return User{}, fmt.Errorf("refresh token '%s' does not exist", refreshToken)
	}
	for _, u := range users {
		if u.Id == id {
			return u, nil
		}
	}
	return User{}, fmt.Errorf("refresh token does not match a user")
}

func NewPayloadFromUser(u User) (Payload, error) {
	return Payload{Id: u.Id, Username: u.Username}, nil
}

func NewRefreshTokenFromUser(user User) (string, error) {
	refreshToken, err := ksuid.NewRandom()
	if err != nil {
		return "", err
	}
	refreshTokenStore[refreshToken.String()] = user.Id
	return refreshToken.String(), nil
}

func ValidateRefreshTokenFromPayload(refreshToken string, payload Payload) error {
	id, ok := refreshTokenStore[refreshToken]
	if !ok {
		return fmt.Errorf("refresh token '%s' not found", refreshToken)
	}
	if payload.Id != id {
		return fmt.Errorf("payload id does not match refresh token id")
	}
	return nil
}

func RevokeRefreshToken(refreshToken string) error {
	delete(refreshTokenStore, refreshToken)
	return nil
}
