package main

import (
	"compress/gzip"
	"errors"
	"io"
	"io/ioutil"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type TestEnv struct {
	appServer  *httptest.Server
	AppHandler func(http.ResponseWriter, *http.Request)
	AppCount   int

	authServer  *httptest.Server
	AuthHandler func(http.ResponseWriter, *http.Request)
	AuthCount   int

	ProtectedUrl       string
	protectedAppServer *httptest.Server
}

func (env *TestEnv) dispose() {
	defer env.appServer.Close()
	defer env.authServer.Close()
	defer env.protectedAppServer.Close()
}

const wwwhisperUsername = "alice"
const wwwhisperPassword = "sometestpassword"

func authQuery(path string) string {
	return "/wwwhisper/auth/api/is-authorized/?path=" + path
}

func checkBasicAuthCredentials(req *http.Request) error {
	username, password, ok := req.BasicAuth()
	if !ok {
		return errors.New("credentials missing")
	}
	if username != wwwhisperUsername || password != wwwhisperPassword {
		return errors.New("credentials do not match")
	}
	return nil
}

func newTestEnv(t *testing.T) *TestEnv {
	var env TestEnv
	env.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("Hello world"))
	}
	env.appServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		env.AppHandler(rw, req)
		env.AppCount++
	}))
	env.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("allowed"))
	}
	env.authServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		err := checkBasicAuthCredentials(req)
		if err != nil {
			t.Error("Auth request basic auth:", err)
			return
		}
		env.AuthHandler(rw, req)
		env.AuthCount++
	}))

	options := &slog.HandlerOptions{}
	handler := slog.NewTextHandler(io.Discard, options)
	log := slog.New(handler)

	parsedUrl, _ := url.Parse(env.authServer.URL)
	parsedUrl.User = url.UserPassword(wwwhisperUsername, wwwhisperPassword)
	env.protectedAppServer = httptest.NewServer(
		WWWhisper(parsedUrl.String(), log, ProxyHandler(env.appServer.URL, log, false)))
	env.ProtectedUrl = env.protectedAppServer.URL
	return &env
}

func assertResponse(t *testing.T, resp *http.Response, err error, expectedStatus int, expectedBody *string) {
	if err != nil {
		t.Fatal("Failed to make request:", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != expectedStatus {
		t.Fatalf("Expected status %v; got %v", expectedStatus, resp.StatusCode)
	}

	if expectedBody != nil {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal("Failed to read response body:", err)
		}
		if string(body) != *expectedBody {
			t.Fatalf("Expected body '%s'; got '%s'", *expectedBody, string(body))
		}
	}
}

func TestAppRequestAllowed(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		siteUrl := req.Header.Get("Site-Url")
		if siteUrl != testEnv.ProtectedUrl {
			t.Error("Invalid Site-Url header", siteUrl)
			return
		}
		if req.URL.RequestURI() != authQuery("/hello") {
			// No t.Fatal in request handlers because go panic recovery
			// reruns panicked handlers and causes test error to be printed
			// twice
			t.Error("Invalid auth request URI", req.URL.RequestURI())
			return
		}
		rw.Write([]byte("allowed"))
	}

	resp, err := http.Get(testEnv.ProtectedUrl + "/hello")
	expectedBody := "Hello world"
	assertResponse(t, resp, err, http.StatusOK, &expectedBody)
	if testEnv.AuthCount != 1 {
		t.Fatal("Auth request not made")
	}
	if testEnv.AppCount != 1 {
		t.Fatal("App request not made")
	}
}

func TestAppRequestLoginNeeded(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.RequestURI() != authQuery("/foobar") {
			t.Error("Invalid auth request URI", req.URL.RequestURI())
			return
		}
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("login required"))
	}

	resp, err := http.Get(testEnv.ProtectedUrl + "/foobar")
	expectedBody := "login required"
	assertResponse(t, resp, err, http.StatusUnauthorized, &expectedBody)
	if testEnv.AuthCount != 1 {
		t.Fatal("Auth request not made")
	}
	if testEnv.AppCount != 0 {
		t.Fatal("App request made")
	}
}

func TestAuthPathAllowed(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/wwwhisper/auth/login" {
			t.Error("Invalid request path", req.URL.Path)
			return
		}
		rw.Write([]byte("login response"))
	}

	resp, err := http.Get(testEnv.ProtectedUrl + "/wwwhisper/auth/login")
	expectedBody := "login response"
	assertResponse(t, resp, err, http.StatusOK, &expectedBody)
	if testEnv.AuthCount != 1 {
		t.Fatal("Auth request not made")
	}
	if testEnv.AppCount != 0 {
		t.Fatal("App request made")
	}
}

func TestPathNormalization(t *testing.T) {
	test_cases := []struct {
		path_in  string
		path_out string
	}{
		{"/", "/"},
		{"/foo/bar", "/foo/bar"},
		{"/foo/bar/", "/foo/bar/"},
		{"/auth/api/login/../../../foo/", "/foo/"},
		{"//", "/"},
		{"", "/"},
		{"/../", "/"},
		{"/./././", "/"},
		{"/./././", "/"},
		{"/foo/./bar/../../bar", "/bar"},
		{"/foo/./bar/%2E%2E/%2E%2E/bar", "/bar"},
		{"/./././/", "/"},
		{"/x/y%2Fz", "/x/y/z"},
		{"", "/"},
		{"///", "/"},
	}
	var expected_path string
	testEnv := newTestEnv(t)
	defer testEnv.dispose()
	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.RequestURI() != authQuery(expected_path) {
			t.Error("Invalid auth request path", req.URL.RequestURI(), expected_path)
			return
		}
		rw.Write([]byte("allowed"))
	}
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.RequestURI() != expected_path {
			t.Error("Invalid app request path", req.URL.RequestURI(), expected_path)
			return
		}
		rw.Write([]byte("ok"))
	}

	for _, test := range test_cases {
		t.Run("path normalization["+test.path_in+"]", func(t *testing.T) {
			expected_path = test.path_out
			resp, err := http.Get(testEnv.ProtectedUrl + test.path_in)
			expectedBody := "ok"
			assertResponse(t, resp, err, http.StatusOK, &expectedBody)
		})
	}
}

func TestAdminPathAllowed(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		siteUrl := req.Header.Get("Site-Url")
		if siteUrl != testEnv.ProtectedUrl {
			t.Error("Invalid Site-Url header", siteUrl)
			return
		}

		if testEnv.AuthCount == 0 {
			if req.URL.RequestURI() != authQuery("/wwwhisper/admin/x") {
				t.Error("Invalid auth request URI", req.URL.RequestURI())
				return
			}
			rw.WriteHeader(http.StatusOK)
		} else {
			if req.URL.RequestURI() != "/wwwhisper/admin/x?foo=bar" {
				t.Error("Invalid admin request URI", req.URL.RequestURI())
				return
			}
			rw.Write([]byte("admin page"))
		}
	}

	resp, err := http.Get(testEnv.ProtectedUrl + "/wwwhisper/admin/x?foo=bar")
	expectedBody := "admin page"
	assertResponse(t, resp, err, http.StatusOK, &expectedBody)
	if testEnv.AuthCount != 2 {
		t.Fatal("Auth requests not made")
	}
	if testEnv.AppCount != 0 {
		t.Fatal("App request made")
	}
}

func TestAdminPostRequest(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		siteUrl := req.Header.Get("Site-Url")
		if siteUrl != testEnv.ProtectedUrl {
			t.Error("Invalid Site-Url header", siteUrl)
			return
		}

		if testEnv.AuthCount == 0 {
			if req.URL.RequestURI() != authQuery("/wwwhisper/admin/submit") {
				t.Error("Invalid auth request URI", req.URL.RequestURI())
				return
			}
			rw.WriteHeader(http.StatusOK)
		} else {
			if req.Method != "POST" {
				t.Error("Invalid request Method", req.Method)
			}
			if req.URL.RequestURI() != "/wwwhisper/admin/submit" {
				t.Error("Invalid admin request URI", req.URL.RequestURI())
				return
			}
			if req.Header.Get("Content-Type") != "text/plain" {
				t.Error("Invalid content encoding", req.Header.Get("Content-Type"))
			}
			body, err := io.ReadAll(req.Body)
			if err != nil || string(body) != "post-data" {
				t.Error("Invalid requst body", string(body), err)
			}
			rw.Write([]byte("OK"))
		}
	}

	postUrl := testEnv.ProtectedUrl + "/wwwhisper/admin/submit"
	resp, err := http.Post(postUrl, "text/plain", strings.NewReader("post-data"))
	expectedBody := "OK"
	assertResponse(t, resp, err, http.StatusOK, &expectedBody)
	if testEnv.AuthCount != 2 {
		t.Fatal("Auth requests not made")
	}
	if testEnv.AppCount != 0 {
		t.Fatal("App request made")
	}
}

func TestProxyVersionPassed(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		userAgent := req.Header.Get("User-Agent")
		// Custom User Agent is only passed with the
		// /wwwhisper/auth/is-authorized request, all other requests
		// should receive the original User Agent.
		if strings.Contains(req.URL.RequestURI(), "/is-authorized") {
			if req.Header.Get("User-Agent") != "go-"+Version {
				t.Error("Invalid is-authorized user agent", userAgent)
			}
		} else {
			if req.Header.Get("User-Agent") != "test-agent" {
				t.Error("Invalid auth user agent", userAgent)
			}
		}

		rw.Write([]byte("auth response"))
	}
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		userAgent := req.Header.Get("User-Agent")
		if req.Header.Get("User-Agent") != "test-agent" {
			t.Error("Invalid app user agent", userAgent)
		}
		rw.Write([]byte("hello"))
	}
	req, _ := http.NewRequest("GET", testEnv.ProtectedUrl, nil)
	req.Header.Set("User-Agent", "test-agent")
	client := &http.Client{}
	resp, err := client.Do(req)
	expectedBody := "hello"

	assertResponse(t, resp, err, http.StatusOK, &expectedBody)
	if testEnv.AuthCount != 1 {
		t.Fatal("Auth request not made")
	}
	if testEnv.AppCount != 1 {
		t.Fatal("App request not made")
	}

	// /wwwhisper/admin requests should also carry the original User Agent
	req, _ = http.NewRequest("GET", testEnv.ProtectedUrl+"/wwwhisper/admin/", nil)
	req.Header.Set("User-Agent", "test-agent")
	resp, err = client.Do(req)
	expectedBody = "auth response"
	assertResponse(t, resp, err, http.StatusOK, &expectedBody)
	if testEnv.AuthCount != 3 {
		t.Fatal("Auth requests not made")
	}
	if testEnv.AppCount != 1 {
		t.Fatal("App request  made")
	}
}

func TestRedirectPassedFromAppToClient(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("location", "https://localhost:9999/foo/bar")
		rw.WriteHeader(302)
		rw.Write([]byte("redirect"))
	}

	// Not using http.Get() because it follows redirects.
	req, _ := http.NewRequest("GET", testEnv.ProtectedUrl+"/foobar", nil)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Disable following HTTP redirects.
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	expectedBody := "redirect"
	assertResponse(t, resp, err, 302, &expectedBody)
	location := resp.Header.Get("location")
	if location != "https://localhost:9999/foo/bar" {
		t.Fatal("Location header not returned to client", location)
	}
	if testEnv.AuthCount != 1 {
		t.Fatal("Auth request not made")
	}
	if testEnv.AppCount != 1 {
		t.Fatal("App request not made")
	}
}

func TestIframeInjection(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()
	responseUnmodified := "<html><body>foo</body></html>"

	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Content-Type", "text/html")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(responseUnmodified))
	}
	resp, err := http.Get(testEnv.ProtectedUrl + "/foo")
	expectedBody := "<html><body>foo\n" +
		"<script src=\"/wwwhisper/auth/iframe.js\"></script>\n" +
		"</body></html>"
	assertResponse(t, resp, err, 200, &expectedBody)

	// Iframe should not be injected to not HTML responses
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(responseUnmodified))
	}
	resp, err = http.Get(testEnv.ProtectedUrl + "/foo")
	assertResponse(t, resp, err, 200, &responseUnmodified)

	// Iframe should not be injected to gzipped HTML responses
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Content-Type", "text/html")
		rw.Header().Add("Content-Encoding", "gzip")
		rw.WriteHeader(http.StatusOK)

		gz := gzip.NewWriter(rw)
		defer gz.Close()
		gz.Write([]byte(responseUnmodified))
	}
	resp, err = http.Get(testEnv.ProtectedUrl + "/foo")
	assertResponse(t, resp, err, 200, &responseUnmodified)

	// Iframe should not be injected HTML responses without the closing </body> tag.
	responseNoBody := "<html><head>foo</head></html>"
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(responseNoBody))
	}
	resp, err = http.Get(testEnv.ProtectedUrl + "/foo")
	assertResponse(t, resp, err, 200, &responseNoBody)

	// Iframe should not be injected wwwhisper backend responses.
	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Content-Type", "text/html")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(responseUnmodified))
	}
	resp, err = http.Get(testEnv.ProtectedUrl + "/wwwhisper/admin")
	assertResponse(t, resp, err, 200, &responseUnmodified)
}
