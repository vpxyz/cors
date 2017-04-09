# CORS Filter for Golang

Another CORS filter middleware for Golang `net/http` handler. 

Like some other CORS filters (e.g. the Jetty's CORS filter), you can define your AllowedMethod list, even non standard. As default, AllowedMethods list is "GET,POST,HEAD,OPTIONS".

*Warning*: if you don't add "OPTIONS" to your AllowedMethod list, the filter can't handle preflight request.

This CORS Filter can forward preflight request.

## Getting Started

The package is go gettable:  go get -u github.com/vpxyz/cors

### Example

``` go
package main

import (
	"github.com/vpxyz/cors"
	"log"
	"net/http"
	"os"
)

func main() {
	logger := log.New(os.Stdout, "CORS: ", log.LstdFlags)

	corsMiddleware := cors.Filter(cors.Config{
		AllowedOrigins:   "http://foobar.com, http://*.example.com", // origins
		AllowedMethods:   cors.DefaultAllowedMethods + "," + http.MethodPut, // put here your allowed methods
		AllowedHeaders:   cors.DefaultAllowedHeaders + ",X-Custom-Header,X-Requested-With",   // allowed headers
		MaxAge:           3000, // indicates how long the results of a preflight request can be cached (default 1800)
		ExposedHeaders:   "X-Custom-Header", // exposer headers
		AllowCredentials: true, // indicates that request whether include credentials
		ForwardRequest:   true, // if true, preflight request are forwarded to handler (dafault false)
		Logger:           logger, // optional logger
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{\"hello\": \"world\"}"))
			return
		}
		if r.Method == "OPTIONS" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{\"forward\": \"request\"}"))
			return
		}
	})

	http.ListenAndServe(":3000", corsMiddleware(handler))
}
```

And now, test preflight request:

``` shell
curl -H "Origin: http://foobar.com" -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: X-Requested-With" -X OPTIONS --verbose   http://localhost:3000  
```
