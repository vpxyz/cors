// Package cors CORS filter middleware for Golang `net/http` handler.
// Like some other CORS filters (e.g. the Jetty's CORS filter), you can define your AllowedMethod list, even non standard. As default, AllowedMethods list is "GET,POST,HEAD,OPTIONS".
package cors

import (
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const (
	// DefaultAllowedOrigin default origin allowed, as default all origins are allowed
	DefaultAllowedOrigin = "*"

	// DefaultAllowedMethods default allowed method, "OPTIONS" method must added if you want handle preflight request
	DefaultAllowedMethods = http.MethodGet + "," + http.MethodPost + "," + http.MethodHead + "," + http.MethodOptions

	// DefaultAllowedHeaders default allowed headers
	DefaultAllowedHeaders = "Origin,Accept,Content-Type,Accept-Language,Content-Language,Last-Event-ID"

	// DefaultMaxAge default number of seconds that preflight requests can be cached by the client.
	DefaultMaxAge = 1800

	// AccessControlAllowOrigin header
	AccessControlAllowOrigin = "Access-Control-Allow-Origin"

	// AccessControlExposeHeaders header
	AccessControlExposeHeaders = "Access-Control-Expose-Headers"

	// AccessControlControlMaxAge header
	AccessControlControlMaxAge = "Access-Control-Max-Age"

	// AccessControlAllowMethods header
	AccessControlAllowMethods = "Access-Control-Allow-Methods"

	// AccessControlAllowHeaders header
	AccessControlAllowHeaders = "Access-Control-Allow-Headers"

	// AccessControlAllowCredentials header
	AccessControlAllowCredentials = "Access-Control-Allow-Credentials"

	// AccessControlRequestMethod header
	AccessControlRequestMethod = "Access-Control-Request-Method"

	// AccessControlRequestHeaders header
	AccessControlRequestHeaders = "Access-Control-Request-Headers"

	// OriginHeader header
	OriginHeader = "Origin"

	// AcceptHeader header
	AcceptHeader = "Accept"

	// ContentTypeHeader header
	ContentTypeHeader = "Content-Type"

	// AllowHeader header
	AllowHeader = "Allow"

	// VaryHeader header
	VaryHeader = "Vary"

	// HostHeader header
	HostHeader = "Header"

	// OriginMatchAll header
	OriginMatchAll = "*"
)

// Config cors filter configuration
type Config struct {
	// AllowedOrigins comma separated list of allowed origins (default "*"), may contain whildchar ("*") for e.g. http://*.example.com
	AllowedOrigins,
	// AllowedMethods comma separated list of methods the client is allowed to use
	AllowedMethods,
	// AllowedHeaders comma separated list of non simple headers the client is allowed to use
	AllowedHeaders,
	// ExposedHeaders headers safe to expose
	ExposedHeaders string
	// MaxAge in seconds (exposed only if > 0) indicates how long the results of a preflight request can be cached
	MaxAge int
	// AllowCredentials if true, indicates that request whether include credentials
	AllowCredentials bool
	// ForwardRequest forward request after preflight
	ForwardRequest bool
	// Logger optional logger
	Logger *log.Logger
}

// cors the filter struct
type cors struct {
	logger         *log.Logger
	allowedOrigins []*regexp.Regexp // store pre-compiled regular expression to match
	// the next two array are used to speedup match of headers and methods
	allowedMethods   map[string]bool
	allowedHeaders   map[string]bool
	hostName         string
	maxAge           string
	exposedHeaders   string
	exposeHeader     bool
	allowAllOrigins  bool
	allowAllHeaders  bool
	allowCredentials bool
	forwardRequest   bool
	// the next two variable store the original strings, header can be in any case, but the match is byte-case-insensitive
	allowedHeadersString string
	allowedMethodsString string
}

// allowed build maps of allowed values
func allowed(allowed []string) (m map[string]bool) {
	m = make(map[string]bool)

	for _, a := range allowed {
		m[a] = true
	}

	return m
}

// normalizeHeaders return an array of headers in uppercase, comma separated and space trimmed.
// the header match is byte-case-insensitive
func normalizeHeaders(headers string) (hl []string) {
	hl = strings.Split(strings.ToUpper(headers), ",")
	for i, v := range hl {
		hl[i] = strings.TrimSpace(v)
	}
	return hl

}

// initialize initialize the cors filter
func initialize(config Config) (c *cors) {
	// assume some dafault
	c = &cors{
		allowedMethods:       allowed(strings.Split(DefaultAllowedMethods, ",")),
		allowedMethodsString: DefaultAllowedMethods,
		allowedHeaders:       allowed(normalizeHeaders(DefaultAllowedHeaders)),
		allowedHeadersString: DefaultAllowedHeaders,
		allowAllOrigins:      true,
		maxAge:               "1800",
	}

	c.logger = config.Logger
	c.forwardRequest = config.ForwardRequest

	if len(config.AllowedOrigins) > 0 && config.AllowedOrigins != "*" {

		// origin match are key sensitive
		origins := strings.Split(config.AllowedOrigins, ",")
		// origins := strings.Split(strings.ToLower(config.AllowedOrigins), ",")

		// now pre-compile pattern for regular expression match
		for _, o := range origins {
			p := regexp.QuoteMeta(strings.TrimSpace(o))
			p = strings.Replace(p, "\\*", ".*", -1)
			p = strings.Replace(p, "\\?", ".", -1)
			r := regexp.MustCompile(p)
			c.allowedOrigins = append(c.allowedOrigins, r)
		}

		c.allowAllOrigins = false
	}

	if len(config.AllowedMethods) > 0 {
		c.allowedMethods = allowed(strings.Split(strings.ToUpper(config.AllowedMethods), ","))
		c.allowedMethodsString = config.AllowedMethods
	}

	if len(config.AllowedHeaders) > 0 {
		if config.AllowedHeaders == strings.TrimSpace("*") {
			c.allowAllHeaders = true
			c.allowedHeadersString = "*"
		} else {
			headers := normalizeHeaders(config.AllowedHeaders)
			c.allowedHeaders = allowed(headers)
			c.allowedHeadersString = config.AllowedHeaders
		}
	}

	if config.MaxAge > 0 {
		c.maxAge = strconv.Itoa(config.MaxAge)
	}

	if len(config.ExposedHeaders) > 0 {
		c.exposedHeaders = config.ExposedHeaders
		c.exposeHeader = true
	}

	c.allowCredentials = config.AllowCredentials

	c.logWrap("Filter configuration [%s]", c)
	return c
}

// logWrap convenient log wrapper
func (c *cors) logWrap(format string, v ...interface{}) {
	if c.logger == nil {
		return
	}

	c.logger.Printf("[cors] "+format, v...)
}

func (c *cors) String() string {
	var s string

	if c.allowAllOrigins {
		s += "AllowedOrigins: *;"
	} else {
		s += "AllowedOrigins: "
		for _, r := range c.allowedOrigins {
			s += r.String() + ","
		}
		s = s[:len(s)-1] + ";"
	}

	s += " AllowedHeaders: "
	for k, v := range c.allowedHeaders {
		if v {
			s += k + ","
		}
	}
	s = s[:len(s)-1] + ";"

	s += " AllowedMethods: "
	for k, v := range c.allowedMethods {
		if v {
			s += k + ","
		}
	}
	s = s[:len(s)-1] + ";"

	if c.exposeHeader {
		s += " ExposeHeader: true;"
	} else {
		s += " ExposeHeader: false;"
	}

	s += " ExposedHeaders: " + c.exposedHeaders + ";"

	s += " MaxAge: " + c.maxAge + ";"

	if c.forwardRequest {
		s += " ForwardRequest: true"
	} else {
		s += " ForwardRequest: false"
	}

	return s
}

// isOriginAllowed return true if the origin is allowed
func (c *cors) isOriginAllowed(origin string) bool {
	if c.allowAllOrigins {
		return true
	}

	// origin = strings.ToLower(origin)

	for _, o := range c.allowedOrigins {

		if o.MatchString(origin) {
			return true
		}
	}

	return false
}

// isMethodAllowed return true if the method is allowed
func (c *cors) isMethodAllowed(method string) bool {
	v, ok := c.allowedMethods[method]

	if !ok {
		return false
	}

	return v
}

// areReqHeadersAllowed return true if the request headers are allowed
func (c *cors) areReqHeadersAllowed(reqHeaders string) bool {

	if c.allowAllHeaders || len(reqHeaders) == 0 {
		return true
	}

	for _, header := range normalizeHeaders(reqHeaders) {
		// check if header are allowed
		if _, ok := c.allowedHeaders[header]; !ok {
			return false
		}
	}
	return true
}

// Filter cors filter middleware
func Filter(config Config) (fn func(next http.Handler) http.Handler) {
	c := initialize(config)

	fn = func(next http.Handler) http.Handler {

		filter := func(w http.ResponseWriter, r *http.Request) {

			origin := r.Header.Get(OriginHeader)

			// It's a same origin request ?
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Allways add "Vary:Origin" header
			w.Header().Add(VaryHeader, OriginHeader)

			if !c.isOriginAllowed(origin) {
				c.logWrap("Origin %+v from %s not allowed", origin, r.RemoteAddr)
				w.WriteHeader(http.StatusForbidden)
				// exit chain
				return
			}

			// handle cors request common parts
			if !c.isMethodAllowed(r.Method) {
				c.logWrap("Request method %+v from %s not allowed", r.Method, r.RemoteAddr)
				w.WriteHeader(http.StatusMethodNotAllowed)
				// exit chain
				return
			}

			// Ok, origin and method are allowed
			w.Header().Add(AccessControlAllowOrigin, origin)

			// if it's a prefligth request, handle them

			if r.Method == http.MethodOptions {

				// Add others value to Vary header
				w.Header().Add(VaryHeader, AccessControlRequestMethod+", "+AccessControlRequestHeaders)

				c.logWrap("Preflight request from %s", r.RemoteAddr)

				acReqMethod := strings.ToUpper(r.Header.Get(AccessControlRequestMethod))

				if !c.isMethodAllowed(acReqMethod) {
					c.logWrap("Preflight request not valid, requested method %s non allowed", acReqMethod)
					w.WriteHeader(http.StatusMethodNotAllowed)
					// exit chain
					return
				}

				acReqHeaders := r.Header.Get(AccessControlRequestHeaders)

				if !c.areReqHeadersAllowed(acReqHeaders) {
					c.logWrap("Preflight request not valid, request headers not allowed")
					w.WriteHeader(http.StatusForbidden)
					// exit chain
					return
				}

				w.Header().Add(AccessControlAllowMethods, c.allowedMethodsString)

				if !c.allowAllHeaders {
					w.Header().Add(AccessControlAllowHeaders, c.allowedHeadersString)
				} else {
					// return the list of requested headers
					w.Header().Add(AccessControlAllowHeaders, acReqHeaders)
				}

				if c.allowCredentials {
					w.Header().Add(AccessControlAllowCredentials, "true")
				}

				if c.maxAge != "0" {
					w.Header().Add(AccessControlControlMaxAge, c.maxAge)
				}

				// forward request if required
				if c.forwardRequest {
					next.ServeHTTP(w, r)
					return
				}
				// exit chain with status HTTP 200
				w.WriteHeader(http.StatusOK)
				return
			}

			c.logWrap("Request from %+v", r.RemoteAddr)

			if c.exposeHeader {
				w.Header().Add(AccessControlExposeHeaders, c.exposedHeaders)
			}

			if c.allowCredentials {
				w.Header().Add(AccessControlAllowCredentials, "true")
			}

			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(filter)
	}

	return fn
}
