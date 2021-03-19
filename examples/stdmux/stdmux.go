package main

import (
	"log"
	"net/http"
	"os"

	"github.com/vpxyz/cors"
)

func main() {
	logger := log.New(os.Stdout, "CORS: ", log.LstdFlags)

	corsMiddleware := cors.Filter(cors.Config{
		AllowedOrigins:   "http://foobar.com, http://*.example.com",                        // origins
		AllowedMethods:   cors.DefaultAllowedMethods + "," + http.MethodPut,                // put here your allowed methods
		AllowedHeaders:   cors.DefaultAllowedHeaders + ",X-Custom-Header,X-Requested-With", // some allowed headers
		MaxAge:           3000,                                                             // indicates how long the results of a preflight request can be cached (default 1800)
		ExposedHeaders:   "X-Custom-Header",                                                // exposer headers
		AllowCredentials: true,                                                             // indicates that request whether include credentials
		ForwardRequest:   true,                                                             // if true, preflight request are forwarded to handler (dafault false)
		Logger:           logger,                                                           // optional logger
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
