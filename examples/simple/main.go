package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/goaway-auth/goaway"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

type user struct {
	Id       uint   `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
}

var users = []user{
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

var refreshTokenStore map[string]uint = make(map[string]uint)

func init() {
	if err := godotenv.Load("./examples/example.env"); err != nil {
		log.Fatal("could not load env")
	}
}

func main() {
	gw := goaway.NewGoAway(goaway.GoAwayFunctions{
		GetUserFromName:      getUserFromName,
		GetUserFromID:        getUserFromID,
		ValidateUser:         validateUser,
		GetUserID:            getUserID,
		GeneratePayload:      generatePayload,
		AddToTokenStore:      addToTokenStore,
		GetFromTokenStore:    getFromTokenStore,
		DeleteFromTokenStore: deleteFromTokenStore,
	})

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

func getUserFromName(username string) (interface{}, error) {
	for _, u := range users {
		if u.Username == username {
			return u, nil
		}
	}
	return nil, fmt.Errorf("user '%s' not found", username)
}

func getUserFromID(iID interface{}) (interface{}, error) {
	id, ok := iID.(uint)
	if !ok {
		return nil, fmt.Errorf("could not parse id")
	}

	for _, u := range users {
		if u.Id == id {
			return u, nil
		}
	}
	return nil, fmt.Errorf("user with id '%d' not found", id)
}

func validateUser(iUser interface{}, password string) error {
	u, ok := iUser.(user)
	if !ok {
		return fmt.Errorf("could not parse user")
	}
	if u.Password != password {
		return fmt.Errorf("wrong password")
	}
	return nil
}

func getUserID(iUser interface{}) (interface{}, error) {
	u, ok := iUser.(user)
	if !ok {
		return nil, fmt.Errorf("could not parse user")
	}
	return u.Id, nil
}

func generatePayload(iUser interface{}) (interface{}, error) {
	u, ok := iUser.(user)
	if !ok {
		return nil, fmt.Errorf("could not parse user")
	}
	return user{Id: u.Id, Username: u.Username}, nil
}

func addToTokenStore(refreshToken string, iId interface{}) error {
	id, ok := iId.(uint)
	if !ok {
		return fmt.Errorf("could not parse id")
	}
	refreshTokenStore[refreshToken] = id
	return nil
}

func getFromTokenStore(refreshToken string) (interface{}, error) {
	token, ok := refreshTokenStore[refreshToken]
	if !ok {
		return nil, fmt.Errorf("could not find refresh token")
	}
	return token, nil
}

func deleteFromTokenStore(refreshToken string) error {
	delete(refreshTokenStore, refreshToken)
	return nil
}
