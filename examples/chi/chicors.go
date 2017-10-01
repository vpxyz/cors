package main

import (
	"github.com/pressly/chi"
	"github.com/vpxyz/cors"
	"log"
	"net/http"
	"os"
)

func main() {
	logger := log.New(os.Stdout, "CORS: ", log.LstdFlags)

	r := chi.NewRouter()

	c := cors.Filter(cors.Config{
		AllowedOrigins:   "http://foobar.com, http://*.example.com",                        // origins
		AllowedMethods:   cors.DefaultAllowedMethods + "," + http.MethodPut,                // put here your allowed methods
		AllowedHeaders:   cors.DefaultAllowedHeaders + ",X-Custom-Header,X-Requested-With", // some allowed headers
		MaxAge:           3000,                                                             // indicates how long the results of a preflight request can be cached (default 1800)
		ExposedHeaders:   "X-Custom-Header",                                                // exposer headers
		AllowCredentials: true,                                                             // indicates that request whether include credentials
		ForwardRequest:   true,                                                             // if true, preflight request are forwarded to handler (dafault false)
		Logger:           logger,                                                           // optional logger
	})

	r.Use(c)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello CORS!"))
	})

	// Response for a preflight request, when ForwardRequest == true
	r.Options("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ForwardRequest!"))
	})

	panic(http.ListenAndServe(":3000", r))
}
