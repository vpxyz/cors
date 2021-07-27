package cors

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Tests inspired by Jetty CORS filter and github.com/rs/cors

// a simple handler
var testHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Write([]byte("test"))
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
})

func assertHeaders(t *testing.T, resHeaders http.Header, reqHeaders map[string]string) {

	t.Logf("reqHeaders =%+v\n", reqHeaders) // output for debug
	t.Logf("resHeaders =%+v\n", resHeaders) // output for debug

	for name, value := range reqHeaders {
		if actual := strings.Join(resHeaders[name], ", "); !strings.Contains(actual, value) {
			t.Errorf("Invalid header `%s', wanted `%s', got `%s'", name, value, actual)
		}
	}
}

func assertResponse(t *testing.T, res *httptest.ResponseRecorder, responseCode int) {
	if responseCode != res.Code {
		t.Errorf("expected response code to be %d but got %d. ", responseCode, res.Code)
	}
}

func TestNoConfig(t *testing.T) {
	f := Filter(Config{})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "",
		"Access-Control-Allow-Origin":      "",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	// check if request arrives to application
	assertResponse(t, res, http.StatusOK)
}

func TestMatchAllOrigin(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "*",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foobar.com")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin",
		"Access-Control-Allow-Origin":      "http://foobar.com",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	assertResponse(t, res, http.StatusOK)
}

func TestAllowedOrigin(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://foobar.com",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foobar.com")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin",
		"Access-Control-Allow-Origin":      "http://foobar.com",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	assertResponse(t, res, http.StatusOK)
}

func TestPrefixWildcardOrigin(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://*.bar.com",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foo.bar.com")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin",
		"Access-Control-Allow-Origin":      "http://foo.bar.com",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	assertResponse(t, res, http.StatusOK)
}

func TestRegexWildcardOrigin(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://foo.*.com",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foo.bar.com")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin",
		"Access-Control-Allow-Origin":      "http://foo.bar.com",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	assertResponse(t, res, http.StatusOK)
}

func TestDisallowedOrigin(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://foobar.com",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://barbaz.com")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin",
		"Access-Control-Allow-Origin":      "",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	assertResponse(t, res, http.StatusForbidden)
}

func TestDisallowedWildcardOrigin(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://*.bar.com",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foo.baz.com")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin",
		"Access-Control-Allow-Origin":      "",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	assertResponse(t, res, http.StatusForbidden)
}

func TestMaxAge(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://example.com",
		AllowedMethods: "GET,OPTIONS",
		MaxAge:         10,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://example.com")
	req.Header.Add("Access-Control-Request-Method", "GET")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin",
		"Access-Control-Allow-Origin":      "http://example.com",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "10",
		"Access-Control-Expose-Headers":    "",
	})

	assertResponse(t, res, http.StatusOK)
}

func TestAllowedMethod(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://foobar.com",
		AllowedMethods: "PUT,DELETE,OPTIONS",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foobar.com")
	req.Header.Add("Access-Control-Request-Method", "PUT")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
		"Access-Control-Allow-Origin":      "http://foobar.com",
		"Access-Control-Allow-Methods":     "PUT",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	assertResponse(t, res, http.StatusOK)
}

func TestDisallowedMethod(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://foobar.com",
		AllowedMethods: "PUT,DELETE,OPTIONS",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foobar.com")
	req.Header.Add("Access-Control-Request-Method", "PATCH")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
		"Access-Control-Allow-Origin":      "",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})
	assertResponse(t, res, http.StatusMethodNotAllowed)
}

func TestAllowedHeader(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://foobar.com",
		AllowedHeaders: "X-Header-1,X-Header-2",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foobar.com")
	req.Header.Add("Access-Control-Request-Method", "GET")
	req.Header.Add("Access-Control-Request-Headers", " X-Header-2 ,X-HEADER-1  ")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
		"Access-Control-Allow-Origin":      "http://foobar.com",
		"Access-Control-Allow-Methods":     "GET",
		"Access-Control-Allow-Headers":     "X-Header-1,X-Header-2",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	assertResponse(t, res, http.StatusOK)
}

func TestAllowedWildcardHeader(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://foobar.com",
		AllowedHeaders: "*",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foobar.com")
	req.Header.Add("Access-Control-Request-Method", "GET")
	req.Header.Add("Access-Control-Request-Headers", "X-Header-2, X-HEADER-1")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
		"Access-Control-Allow-Origin":      "http://foobar.com",
		"Access-Control-Allow-Methods":     "GET",
		"Access-Control-Allow-Headers":     "X-Header-2, X-HEADER-1",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	assertResponse(t, res, http.StatusOK)
}

func TestDisallowedHeader(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://foobar.com",
		AllowedHeaders: "X-Header-1,x-header-2",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foobar.com")
	req.Header.Add("Access-Control-Request-Method", "GET")
	req.Header.Add("Access-Control-Request-Headers", "X-Header-3, X-Header-1")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
		"Access-Control-Allow-Origin":      "",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	assertResponse(t, res, http.StatusForbidden)
}

func TestOriginHeader(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://foobar.com",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foobar.com")
	req.Header.Add("Access-Control-Request-Method", "GET")
	req.Header.Add("Access-Control-Request-Headers", "origin")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
		"Access-Control-Allow-Origin":      "http://foobar.com",
		"Access-Control-Allow-Methods":     "GET",
		"Access-Control-Allow-Headers":     "Origin",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	assertResponse(t, res, http.StatusOK)
}

func TestExposedHeader(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://foobar.com",
		ExposedHeaders: "X-Header-1,X-Header-2",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foobar.com")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin",
		"Access-Control-Allow-Origin":      "http://foobar.com",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "X-Header-1,X-Header-2",
	})

	assertResponse(t, res, http.StatusOK)
}

func TestDisableOptionsForwardRequest(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://foobar.com",
		ForwardRequest: false,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foobar.com")
	req.Header.Add("Access-Control-Request-Method", "GET")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
		"Access-Control-Allow-Origin":      "",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	// no forward request for option, return 200
	assertResponse(t, res, http.StatusOK)
}

func TestEnableOptionsForwardRequest(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://foobar.com",
		ForwardRequest: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://foobar.com")
	req.Header.Add("Access-Control-Request-Method", "GET")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
		"Access-Control-Allow-Origin":      "",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	f(testHandler).ServeHTTP(res, req)

	// no method are bound to OPTIONS request
	assertResponse(t, res, http.StatusMethodNotAllowed)

}

func TestHandlePreflightInvalidOriginAbortion(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins: "http://foo.com",
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://example.com")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin",
		"Access-Control-Allow-Origin":      "",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	assertResponse(t, res, http.StatusForbidden)
}

func TestHandlePreflightDefaultOptionsAbortion(t *testing.T) {
	f := Filter(Config{
		// Intentionally left blank.
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://example.com")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "",
		"Access-Control-Allow-Origin":      "",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})

	// fails because preflight request require Access-Control-Request-Method
	assertResponse(t, res, http.StatusMethodNotAllowed)
}

func TestHandleActualRequestAllowsCredentials(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins:   "http://example.com",
		AllowCredentials: true,
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://example.com")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin",
		"Access-Control-Allow-Origin":      "http://example.com",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "true",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})
}

func TestHandleActualRequestIgnoreAllowsCredentials(t *testing.T) {
	f := Filter(Config{
		AllowedOrigins:   "*",
		AllowCredentials: true,
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://example.com")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin",
		"Access-Control-Allow-Origin":      "http://example.com",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})
}

func TestHandleActualRequestInvalidMethodAbortion(t *testing.T) {
	f := Filter(Config{
		AllowedMethods:   "POST",
		AllowCredentials: true,
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://example.com/")

	f(testHandler).ServeHTTP(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary":                             "Origin",
		"Access-Control-Allow-Origin":      "",
		"Access-Control-Allow-Methods":     "",
		"Access-Control-Allow-Headers":     "",
		"Access-Control-Allow-Credentials": "",
		"Access-Control-Max-Age":           "",
		"Access-Control-Expose-Headers":    "",
	})
}

func TestToLower(t *testing.T) {
	var tests = []struct {
		in  string
		out string
	}{
		{"FOOBAR", "foobar"},
		{"FooBar", "foobar"},
		{"FoObaR", "foobar"},
		{"fOOBAr", "foobar"},
		{" FoO BaR ", " foo bar "},
		{"FoO@@Bar", "foo@@bar"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			s := toLowerCase([]byte(tt.in))
			if string(s) != tt.out {
				t.Errorf("got %q, want %q", s, tt.out)
			}
		})
	}
}

func TestNormalizeHeader(t *testing.T) {
	var tests = []struct {
		in  string
		out []string
	}{
		{"FOO", []string{"foo"}},
		{",FOO", []string{"foo"}},
		{"FoO,Bar", []string{"foo", "bar"}},
		{"FoO,BaR,", []string{"foo", "bar"}},
		{"FoO,Bar, ", []string{"foo", "bar"}},
		{",FoO,,,BaR,", []string{"foo", "bar"}},
		{",,FoO,,,BaR,", []string{"foo", "bar"}},
		{"  ,,FoO,,,BaR,  ", []string{"foo", "bar"}},
		{"FoO, Bar, foo;Bar, ", []string{"foo", "bar", "foo;bar"}},
		{"fOo", []string{"foo"}},
		{" Fo O ", []string{"fo o"}},
		{" , ", make([]string, 0)},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			s := normalizeHeaders(tt.in)
			if len(s) != len(tt.out) {
				t.Errorf("got %q, want %q", s, tt.out)
				return
			}
			for i := 0; i < len(tt.out); i++ {
				if i < len(s) && string(s[i]) != tt.out[i] {
					t.Errorf("got %q, want %q", s, tt.out)
				}

			}

		})
	}
}

func TestTrim(t *testing.T) {
	var tests = []struct {
		in  string
		out string
	}{
		{"", ""},
		{"       ", ""},
		{" foo bar", "foo bar"},
		{" foo bar ", "foo bar"},
		{"          foo bar", "foo bar"},
		{"foo bar         ", "foo bar"},
		{"    foo bar     ", "foo bar"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			s := trimSpace([]byte(tt.in))
			if string(s) != tt.out {
				t.Errorf("got %q, want %q", s, tt.out)
			}
		})
	}
}

func TestLogger(t *testing.T) {
	buf := new(bytes.Buffer)
	logger := log.New(buf, "", log.LstdFlags)
	var tests = []struct {
		in      string
		logWrap func(format string, v ...interface{})
		out     string
	}{
		{"test nil", logInit(nil), ""},
		{"test logger", logInit(logger), "test logger"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			tt.logWrap(tt.in)
			s := buf.String()
			t.Logf("s = %s", s)
			if !(s == tt.out || strings.Contains(s, tt.out)) {
				t.Errorf("got %q, want %q", s, tt.out)
			}
			buf.Reset()
		})
	}
}
