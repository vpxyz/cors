package cors

import (
	"bytes"
	"net/http"
	"testing"
)

type FakeResponse struct {
	header http.Header
}

func (r FakeResponse) Header() http.Header {
	return r.header
}

func (r FakeResponse) WriteHeader(n int) {
}

func (r FakeResponse) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func commonBench(b *testing.B, h http.Handler, w http.ResponseWriter, r *http.Request) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(w, r)
	}
}

func BenchmarkWithout(b *testing.B) {
	res := FakeResponse{http.Header{}}
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)

	commonBench(b, testHandler, res, req)
}

func BenchmarkDefault(b *testing.B) {
	res := FakeResponse{http.Header{}}
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://somedomain.com")
	handler := Filter(Config{})(testHandler)

	commonBench(b, handler, res, req)
}

func BenchmarkAllowedOrigin(b *testing.B) {
	res := FakeResponse{http.Header{}}
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://somedomain.com")
	c := Filter(Config{
		AllowedOrigins: "http://somedomain.com",
	})
	handler := c(testHandler)

	commonBench(b, handler, res, req)
}

func BenchmarkAllowedOriginSuffix(b *testing.B) {
	res := FakeResponse{http.Header{}}
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://somedomain.com")
	c := Filter(Config{
		AllowedOrigins: "http://*.somedomain.com",
	})
	handler := c(testHandler)

	commonBench(b, handler, res, req)
}

func BenchmarkAllowedOriginRegex(b *testing.B) {
	res := FakeResponse{http.Header{}}
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://somedomain.com")
	c := Filter(Config{
		AllowedOrigins: "http://*.somedomain.*",
	})
	handler := c(testHandler)

	commonBench(b, handler, res, req)
}

func BenchmarkPreflightNoOrigin(b *testing.B) {
	res := FakeResponse{http.Header{}}
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Access-Control-Request-Method", "GET")
	handler := Filter(Config{})(testHandler)

	commonBench(b, handler, res, req)
}

func BenchmarkPreflightOrigin(b *testing.B) {
	res := FakeResponse{http.Header{}}
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://somedomain.com")
	req.Header.Add("Access-Control-Request-Method", "GET")
	handler := Filter(Config{})(testHandler)

	commonBench(b, handler, res, req)
}

func BenchmarkPreflightHeaderNoOrigin(b *testing.B) {
	res := FakeResponse{http.Header{}}
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Access-Control-Request-Method", "GET")
	req.Header.Add("Access-Control-Request-Headers", "Accept")
	handler := Filter(Config{})(testHandler)

	commonBench(b, handler, res, req)
}

func BenchmarkPreflightHeader(b *testing.B) {
	res := FakeResponse{http.Header{}}
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://somedomain.com")
	req.Header.Add("Access-Control-Request-Method", "GET")
	req.Header.Add("Access-Control-Request-Headers", "Accept")
	handler := Filter(Config{})(testHandler)

	commonBench(b, handler, res, req)
}

func BenchmarkPreflightStrangeHeader(b *testing.B) {
	res := FakeResponse{http.Header{}}
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://somedomain.com")
	req.Header.Add("Access-Control-request-METHOD", "GET")
	req.Header.Add("Access-Control-Request-headers", "Accept")
	handler := Filter(Config{})(testHandler)

	commonBench(b, handler, res, req)
}

var lowerCaseTest = []byte(",BARFOOBAR, foofoofoo,BARBARBARBARfoo,foofooaBAR,BAR , * foobar,,,,foo,,FOOBAR,foofoofooBARfooBAR,FOOBARBARFOORfoo,fooBARfooBARfooBAR,BARfooBAR, FOOBAR; foobar,foo BAR,BAR,FOO, ")

func BenchmarkToLowerCase(b *testing.B) {

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toLowerCase(lowerCaseTest)
	}
}

func BenchmarkToLowerCaseStandard(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bytes.ToLower(lowerCaseTest)
	}
}

func BenchmarkNormalizeHeaders(b *testing.B) {
	lct := string(lowerCaseTest)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		normalizeHeaders(lct)
	}
}

func BenchmarkNormalizeHeadersSimple(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		normalizeHeaders("header, second-header, THIRD-HEADER")
	}
}

func BenchmarkNormalizeHeadersSingle(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		normalizeHeaders("header")
	}
}

func BenchmarkNormalizeHeaderStandard(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := bytes.ToLower(lowerCaseTest)
		ss := bytes.Split(s, []byte(","))
		for j, tmp := range ss {
			ss[j] = bytes.TrimSpace(tmp)
		}

	}
}

func BenchmarkNormalizeHeaderStandardFast(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := toLowerCase(lowerCaseTest)
		ss := bytes.Split(s, []byte(","))
		for j, tmp := range ss {
			ss[j] = trimSpace(tmp)
		}

	}
}

var trimBench = [][]byte{
	[]byte("                FOO   BAR           "),
	[]byte("FOO   BAR           "),
	[]byte("                FOO   BAR"),
	[]byte("FOO   BAR"),
}

func BenchmarkTrim(b *testing.B) {
	b.ReportAllocs()
	for _, tb := range trimBench {
		for i := 0; i < b.N; i++ {
			trimSpace(tb)
		}
	}

}

func BenchmarkTrimStandard(b *testing.B) {
	b.ReportAllocs()
	for _, tb := range trimBench {
		for i := 0; i < b.N; i++ {
			bytes.TrimSpace(tb)
		}
	}
}
