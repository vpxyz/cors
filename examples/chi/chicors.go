package main

import (
	"github.com/pressly/chi"
	"github.com/vpxyz/cors"
	"log"
	"net/http"
	// _ "net/http/pprof"
	"os"
)

func main() {
	logger := log.New(os.Stdout, "CORS: ", log.LstdFlags)

	// run profiler
	// go func() {
	// 	log.Println(http.ListenAndServe("localhost:6060", nil))
	// }()

	r := chi.NewRouter()

	// TODO: testare se è neutro rispetto al protocollo
	c := cors.Filter(cors.Config{
		AllowedOrigins:   "http://*.example.com ,//foobar.com",              // origins
		AllowedMethods:   cors.DefaultAllowedMethods + "," + http.MethodPut, // put here your allowed methods
		AllowedHeaders:   cors.DefaultAllowedHeaders + ",X-Custom-Header",   // allowed headers
		ExposedHeaders:   "X-Custom-Header",                                 // exposer headers
		AllowCredentials: true,
		Logger:           logger,
		ForwardRequest:   true,
	})
	// c := cors.Filter(cors.Config{AllowedOrigins: "http://foobar.com", DebugLogger: logger, ForwardRequest: true})
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
