package main

import (
	"fmt"
	"github.com/go-martini/martini"
	"github.com/go-shaken/apiauth"
)

func authUser(appKey string, userkey string) bool {
	fmt.Println("User is authorized")
	return true
}

func main() {
	apiauth.SetAppAuthHandler(authUser)
	m := martini.Classic()
	m.Get("/", func() string { return "Welcome to the public area\n" })
	m.Post("/authenticate", apiauth.Authenticate())
	m.Get("/protected", apiauth.AuthRequired, func() string { return "Welcome to the protected area\n" })
	m.Get("/protected/data", apiauth.AuthRequired, func() string { return `{ "title":"secret hello","description":"this data is protected" }` })
	m.Get("/protected/fail_auth", apiauth.AuthDenied, func() string { return `{ "title":"secret hello","description":"this data is protected" }` })
	m.Get("/protected/fail_error", func() (int, string) { return 500, "Internal Server Error" })
	m.Run()
}
