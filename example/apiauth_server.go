package main

import (
	"github.com/codegangsta/martini"
	"github.com/pagecr/apiauth"
)

func main() {
	m := martini.Classic()
	m.Get("/", func() string { return "Welcome to the public area\n" })
	m.Post("/authenticate", apiauth.Authenticate())
	m.Get("/protected", apiauth.AuthRequired, func() string { return "Welcome to the protected area\n" })
	m.Run()
}
