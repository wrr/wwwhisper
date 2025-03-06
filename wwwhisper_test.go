package main

import (
	"compress/gzip"
	"errors"
	"io"
	"io/ioutil"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
)

const wwwhisperUsername = "alice"
const wwwhisperPassword = "sometestpassword"

type TestEnv struct {
	appServer  *httptest.Server
	AppHandler func(http.ResponseWriter, *http.Request)
	AppCount   int

	authServer  *httptest.Server
	AuthHandler func(http.ResponseWriter, *http.Request)
	AuthCount   int

	ProtectedURL       string
	protectedAppServer *httptest.Server

	AppProxy *httputil.ReverseProxy
}

func (env *TestEnv) dispose() {
	defer env.appServer.Close()
	defer env.authServer.Close()
	defer env.protectedAppServer.Close()
}

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
	handler := slog.NewTextHandler(io.Discard /*os.Stderr*/, options)
	log := slog.New(handler)

	appUrlParsed, _ := url.Parse(env.appServer.URL)
	env.AppProxy = NewReverseProxy(appUrlParsed, log, false)

	wwwhisperURL, _ := url.Parse(env.authServer.URL)
	wwwhisperURL.User = url.UserPassword(wwwhisperUsername, wwwhisperPassword)
	wwwhisperHandler := NewAuthHandler(wwwhisperURL, log, env.AppProxy)

	env.protectedAppServer = httptest.NewServer(wwwhisperHandler)
	env.ProtectedURL = env.protectedAppServer.URL
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

func clearEnv() {
	os.Unsetenv("WWWHISPER_URL")
	os.Unsetenv("PORT")
	os.Unsetenv("PROXY_TO_PORT")
}

func TestEnvVariablesRequired(t *testing.T) {
	clearEnv()
	defer clearEnv()

	err := run()
	expected := "WWWHISPER_URL environment variable is not set"
	if err == nil || err.Error() != expected {
		t.Fatal("Expected error is missing:", err)
	}

	os.Setenv("WWWHISPER_URL", "https://example.com")
	err = run()
	expected = "PORT environment variable is not set"
	if err == nil || err.Error() != expected {
		t.Fatal("Expected error is missing:", err)
	}

	// Invalid port to ensure the final run() fails.
	os.Setenv("PORT", "1000000")
	err = run()
	expected = "PROXY_TO_PORT environment variable is not set"
	if err == nil || err.Error() != expected {
		t.Fatal("Expected error is missing:", err)
	}

	os.Setenv("PROXY_TO_PORT", "999")
	// All requires environment variables are set, but PORT is too large
	// so the server should fail to bind it.
	err = run()
	if err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatal("Expected error is missing:", err)
	}
}

func TestRunArgsValidation(t *testing.T) {
	err := Run("https://wwwhi sper.io", "8080", "8000", slog.LevelError)
	expected := "wwwhisper url has invalid format: https://wwwhi sper.io"
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatal("Expected error is missing:", err)
	}

	err = Run("https://wwwhisper.io", "8080", "invalidPort", slog.LevelError)
	expected = "App port has invalid format: invalidPort;"
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatal("Expected error is missing:", err)
	}

	err = Run("https://wwwhisper.io", "invalidPort", "8000", slog.LevelError)
	expected = "tcp/invalidPort"
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatal("Expected error is missing:", err)
	}

}

func TestAppRequestAllowed(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		siteURL := req.Header.Get("Site-Url")
		if siteURL != testEnv.ProtectedURL {
			t.Error("Invalid Site-Url header", siteURL)
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

	resp, err := http.Get(testEnv.ProtectedURL + "/hello")
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

	resp, err := http.Get(testEnv.ProtectedURL + "/foobar")
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

	resp, err := http.Get(testEnv.ProtectedURL + "/wwwhisper/auth/login")
	expectedBody := "login response"
	assertResponse(t, resp, err, http.StatusOK, &expectedBody)
	if testEnv.AuthCount != 1 {
		t.Fatal("Auth request not made")
	}
	if testEnv.AppCount != 0 {
		t.Fatal("App request made")
	}
}

func TestAuthRequestNonHttpError(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		// Invalid location header should result in a low level request
		// error returned by the Go client lib, not an HTTP error code.
		rw.Header().Add("location", "https://inv alid")
		rw.WriteHeader(302)
	}

	resp, err := http.Get(testEnv.ProtectedURL + "/foo")
	expectedBody := "Internal server error: auth request\n"
	assertResponse(t, resp, err, 500, &expectedBody)

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
		t.Run("["+test.path_in+"]", func(t *testing.T) {
			expected_path = test.path_out
			resp, err := http.Get(testEnv.ProtectedURL + test.path_in)
			expectedBody := "ok"
			assertResponse(t, resp, err, http.StatusOK, &expectedBody)
		})
	}
}

func TestAdminPathAllowed(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		siteURL := req.Header.Get("Site-Url")
		if siteURL != testEnv.ProtectedURL {
			t.Error("Invalid Site-Url header", siteURL)
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

	resp, err := http.Get(testEnv.ProtectedURL + "/wwwhisper/admin/x?foo=bar")
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
		siteURL := req.Header.Get("Site-Url")
		if siteURL != testEnv.ProtectedURL {
			t.Error("Invalid Site-Url header", siteURL)
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

	postURL := testEnv.ProtectedURL + "/wwwhisper/admin/submit"
	resp, err := http.Post(postURL, "text/plain", strings.NewReader("post-data"))
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
	req, _ := http.NewRequest("GET", testEnv.ProtectedURL, nil)
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
	req, _ = http.NewRequest("GET", testEnv.ProtectedURL+"/wwwhisper/admin/", nil)
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
	req, _ := http.NewRequest("GET", testEnv.ProtectedURL+"/foobar", nil)
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
	resp, err := http.Get(testEnv.ProtectedURL + "/foo")
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
	resp, err = http.Get(testEnv.ProtectedURL + "/foo")
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
	resp, err = http.Get(testEnv.ProtectedURL + "/foo")
	assertResponse(t, resp, err, 200, &responseUnmodified)

	// Iframe should not be injected HTML responses without the closing </body> tag.
	responseNoBody := "<html><head>foo</head></html>"
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(responseNoBody))
	}
	resp, err = http.Get(testEnv.ProtectedURL + "/foo")
	assertResponse(t, resp, err, 200, &responseNoBody)

	// Iframe should not be injected wwwhisper backend responses.
	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Content-Type", "text/html")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(responseUnmodified))
	}
	resp, err = http.Get(testEnv.ProtectedURL + "/wwwhisper/admin")
	assertResponse(t, resp, err, 200, &responseUnmodified)
}

type errorReader struct{}

func (er errorReader) Read(p []byte) (int, error) {
	return 0, errors.New("body read error")
}
func (er errorReader) Close() error {
	return nil
}

func TestIframeInjectionBodyReadFailure(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()
	modifyResponseOrig := testEnv.AppProxy.ModifyResponse
	testEnv.AppProxy.ModifyResponse = func(resp *http.Response) error {
		resp.Body = errorReader{}
		return modifyResponseOrig(resp)
	}

	responseUnmodified := "<html><body>foo</body></html>"
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Content-Type", "text/html")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(responseUnmodified))
	}

	// Error returned by the default AppProxy.ErrorHandler
	// when ModifyResponse returns an error.
	expectedBody := ""
	resp, err := http.Get(testEnv.ProtectedURL + "/foo")
	assertResponse(t, resp, err, 502, &expectedBody)
}

func TestStringToLogLevel(t *testing.T) {
	test_cases := []struct {
		level_in  string
		level_out slog.Level
	}{
		// All levels are case insensitive.
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"deBuG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"", slog.LevelWarn},
		{"error", slog.LevelError},
		{"off", slog.LevelError + 1},
		// Any not recognized setting is mapped to info
		{"on", slog.LevelInfo},
		{"1", slog.LevelInfo},
	}

	for _, test := range test_cases {
		t.Run(test.level_in, func(t *testing.T) {
			out := stringToLogLevel(test.level_in)
			if test.level_out != out {
				t.Errorf("expected: %s, got: %s", test.level_out, out)
			}
		})
	}
}
