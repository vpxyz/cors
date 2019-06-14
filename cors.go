// Package cors CORS filter middleware for Golang `net/http` handler.
// Like some other CORS filters (e.g. the Jetty's CORS filter), you can define your AllowedMethod list, even non standard. As default, AllowedMethods list is "GET,POST,HEAD,OPTIONS".
package cors

import (
	"bytes"
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
	logger               *log.Logger
	allowedRegexOrigins  []*regexp.Regexp // store pre-compiled regular expression to match
	allowedStaticOrigins []string         // store static origin to match
	allowedSuffixOrigins []string         // store suffix origin to match
	// the next tho maps are used to speedup match of headers and methods
	allowedMethods map[string]bool
	allowedHeaders map[string]bool
	// the next two variable store the original strings, header can be in any case, but the match is byte-case-insensitive
	allowedHeadersString string
	allowedMethodsString string
	hostName             string
	maxAge               string
	exposedHeaders       string
	exposeHeader         bool
	allowAllOrigins      bool
	allowAllHeaders      bool
	allowCredentials     bool
	forwardRequest       bool
}

// allowed build maps of allowed values
func allowed(allowed [][]byte) (m map[string]bool) {
	m = make(map[string]bool)

	for _, a := range allowed {
		m[string(a)] = true
	}

	return m
}

// toLowerCase convert s to lower case, s must contains only ASCII chars
func toLowerCase(s []byte) []byte {
	for i, c := range s {
		if 'A' <= c && c <= 'Z' {
			s[i] = c ^ 0x20
		}
	}

	return s

}

// trimSpace trim space of an ASCII array of byte (like the http headers)
func trimSpace(s []byte) []byte {
	start := 0
	end := len(s) - 1
	for ; start < len(s) && s[start] == ' '; start++ {
	}
	for ; end > 0 && s[end] == ' '; end-- {
	}
	return s[start : end+1]

}

// normalizeHeaders return an array of headers, in lower case and space trimmed.
// the header match is byte-case-insensitive
func normalizeHeaders(headers string) (ss [][]byte) {
	const sep byte = ','       // headers separator
	ss = make([][]byte, 0, 16) // assume that usally an header value contains less then 16 distinct values
	start := 0
	s := []byte(headers)
	for i, c := range s {
		// to lower case
		if 'A' <= c && c <= 'Z' {
			s[i] = c ^ 0x20
			continue
		}

		// Skip separator in the head, in the tail, and or sequence like ",,,,"
		if s[i] == sep && start == i {
			start++
			continue
		}
		if s[i] == sep {
			ss = append(ss, trimSpace(s[start:i]))
			start = i + 1
		}
	}

	// if start < len(s) , we need to copy the tail of the string
	if start < len(s) {
		ss = append(ss, trimSpace(s[start:len(s)]))
	}

	// if there isn't any sep in s, put s in ss
	if len(ss) == 0 {
		ss = append(ss, trimSpace(s[start:len(s)]))
	}

	return ss
}

// initialize initialize the cors filter
func initialize(config Config) (c *cors) {
	// assume some dafault
	c = &cors{
		allowedMethods:       allowed(bytes.Split([]byte(DefaultAllowedMethods), []byte(","))),
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

		// different type of origins...
		for _, o := range origins {
			if strings.IndexAny(o, "*") == -1 {
				c.allowedStaticOrigins = append(c.allowedStaticOrigins, o)
			} else if strings.Index(o, "*.") == 0 {
				c.allowedSuffixOrigins = append(c.allowedSuffixOrigins, o[2:len(o)])
			} else if strings.Count(o, "*") > 0 || strings.Count(o, "?") > 0 {
				p := regexp.QuoteMeta(strings.TrimSpace(o))
				p = strings.Replace(p, "\\*", ".*", -1)
				p = strings.Replace(p, "\\?", ".", -1)
				r := regexp.MustCompile(p)
				c.allowedRegexOrigins = append(c.allowedRegexOrigins, r)
			}
		}

		c.allowAllOrigins = false
	}

	if len(config.AllowedMethods) > 0 {
		c.allowedMethods = allowed(bytes.Split(bytes.ToUpper([]byte(config.AllowedMethods)), []byte(",")))
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

	if config.AllowCredentials && c.allowAllOrigins {
		c.logWrap("Ignore AllowCredentials = true. It's a security issue set up AllowOrigin==* and AllowCredientials==true.")
	} else {
		c.allowCredentials = config.AllowCredentials
	}

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
		for _, r := range c.allowedRegexOrigins {
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

	for _, o := range c.allowedStaticOrigins {
		if o == origin {
			return true
		}
	}

	for _, o := range c.allowedSuffixOrigins {
		if len(origin) >= len(o) && strings.HasSuffix(origin, o) {
			return true
		}
	}

	for _, o := range c.allowedRegexOrigins {
		if o.MatchString(origin) {
			return true
		}
	}

	return false
}

// isMethodAllowed return true if the method is allowed
func (c *cors) isMethodAllowed(method string) bool {
	return c.allowedMethods[method]
}

// areReqHeadersAllowed return true if the request headers are allowed
func (c *cors) areReqHeadersAllowed(reqHeaders string) bool {
	if c.allowAllHeaders || len(reqHeaders) == 0 {
		return true
	}

	for _, header := range normalizeHeaders(reqHeaders) {
		// check if header are allowed
		// The compiler recognizes m[string(byteSlice)] as a special case, no conversion happens
		if !c.allowedHeaders[string(header)] {
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

			// if it's a simple cross-origin request, handle them
			if r.Method != http.MethodOptions {

				c.logWrap("Request from %+v", r.RemoteAddr)

				if c.exposeHeader {
					w.Header().Add(AccessControlExposeHeaders, c.exposedHeaders)
				}

				if c.allowCredentials {
					w.Header().Add(AccessControlAllowCredentials, "true")
				}

				next.ServeHTTP(w, r)
				return
			}

			// No, it's a prefligth request, handle them

			// Add others value to Vary header
			w.Header().Add(VaryHeader, AccessControlRequestMethod+", "+AccessControlRequestHeaders)

			c.logWrap("Preflight request from %s", r.RemoteAddr)

			acReqMethod := r.Header.Get(AccessControlRequestMethod)

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

			if c.allowAllHeaders {
				// return the list of requested headers
				w.Header().Add(AccessControlAllowHeaders, acReqHeaders)

			} else {
				w.Header().Add(AccessControlAllowHeaders, c.allowedHeadersString)
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

		return http.HandlerFunc(filter)
	}

	return fn
}
