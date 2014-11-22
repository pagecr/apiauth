package apiauth

import (
	"github.com/go-martini/martini"
	"net/http"
)

func CorsHandler() martini.Handler {
	return func(c martini.Context, res http.ResponseWriter, req *http.Request) {
		o := req.Header.Get("Origin")
		if o != "" {
			res.Header().Add("Access-Control-Allow-Origin", o)
			if req.Method == "OPTIONS" {
				// methods permited by sever
				res.Header().Add("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				// custom headers permited by sever
				res.Header().Add("Access-Control-Allow-Headers", "X-Authorization")
				// cookies allowed by server?
				//res.Header().Add("Access-Control-Allow-Credentials", "{true/false}"

				// permit browser to show these headers
				//res.Header().Add("Access-Control-Expose-Headers", "X-Authorization")

				// seconds that browser can cache this response
				//res.Header().Add("Access-Control-Max-Age", "{seconds}")
			}
		}
	}
}
