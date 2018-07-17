package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"

	"golang.org/x/oauth2"
	jose "gopkg.in/square/go-jose.v2"
	//"io/ioutil"
)

var authEndPoint = oauth2.Endpoint{
	// https://github.com/coreos/dex/issues/712
	AuthURL:  os.Getenv("ISSUER_URL") + os.Getenv("AUTH_URI"),
	TokenURL: os.Getenv("ISSUER_URL") + os.Getenv("TOKEN_URI"),
}

var (
	oauth2Config = &oauth2.Config{
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Scopes:       []string{"offline_access", "email", "openid", "groups", "profile", "federated:id"}, // https://github.com/coreos/dex/blob/master/server/oauth2.go
		Endpoint:     authEndPoint,
	}
	// Some random string, random for each request
	oauthStateString = "random"
)

const htmlIndex = `<html><body>
<a href="login">Log in</a>
</body></html>
`

func main() {
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	fmt.Println(http.ListenAndServe(":3000", nil))
}
func handleMain(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, htmlIndex)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	url := oauth2Config.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != oauthStateString {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
		return
	}
	log.Println("Code:")
	log.Println(code)

	if state := r.FormValue("state"); state != oauthStateString {
		http.Error(w, fmt.Sprintf("expected state %q got %q", oauthStateString, state), http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		fmt.Fprintf(w, "Error getting token", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Println("Token")
	log.Println(token)

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		return
	}

	refreshToken, ok := token.Extra("refresh_token").(string)
	if !ok {
		http.Error(w, "no refresh_token in token response", http.StatusInternalServerError)
		return
	}

	tokenType, ok := token.Extra("token_type").(string)
	if !ok {
		http.Error(w, "no token_type in token response", http.StatusInternalServerError)
		return
	}

	accessToken, ok := token.Extra("access_token").(string)
	if !ok {
		http.Error(w, "no access_token in token response", http.StatusInternalServerError)
		return
	}

	log.Println("rawIDToken")
	log.Println(rawIDToken)

	jws, err := jose.ParseSigned(rawIDToken)
	if err != nil {
		fmt.Fprintf(w, "odic: malformed jwt", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	accessPayload, err := parseJWT(accessToken)
	if err != nil {
		fmt.Fprintf(w, "access odic: malformed jwt", err)
		accessPayload = []byte("Access token not JWT, no data")
		//http.Error(w, err.Error(), http.StatusInternalServerError)
		//return
	}

	// Throw out tokens with invalid claims before trying to verify the token. This lets
	// us do cheap checks before possibly re-syncing keys.
	payload, err := parseJWT(rawIDToken)
	if err != nil {
		fmt.Fprintf(w, "raw odic: malformed jwt", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//var idToken rawIDToken
	if err := json.Unmarshal(payload, &token); err != nil {
		fmt.Fprintf(w, "odic: failed to unmarshal", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Println("JWS")
	log.Println(reflect.TypeOf(jws))
	log.Println("JWT Access Token Claims Payload")
	log.Println(string(accessPayload))
	log.Println("JWT Raw ID Token Claims Payload")
	log.Println(string(payload))

	var sArray = []string{"<html><head></head><body>", "code", code, "accessToken", accessToken, "tokenType", tokenType, "refreshToken", refreshToken, "rawIDToken", rawIDToken, "rawIDToken - claims", string(payload), "accessToken - claims", string(accessPayload), "</body></html>"}

	var output = strings.Join(sArray, "<br>")
	fmt.Fprintf(w, output)

	// https://github.com/coreos/go-oidc/blob/v2/verify.go
	// https://github.com/coreos/dex/tree/master/cmd/example-app

}

func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	return payload, nil
}
