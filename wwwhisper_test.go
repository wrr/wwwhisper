package main

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
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

	ExternalURL        string
	protectedAppServer *httptest.Server

	AppProxy *httputil.ReverseProxy
}

func (env *TestEnv) dispose() {
	defer env.appServer.Close()
	defer env.authServer.Close()
	defer env.protectedAppServer.Close()
}

func parseURL(urlString string) *url.URL {
	result, _ := url.Parse(urlString)
	return result
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

func findPortToListen(t *testing.T, rangeStart Port) Port {
	for port := rangeStart; port < 0xffff; port++ {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err == nil {
			listener.Close()
			return port
		}
	}
	t.Fatalf("Failed to find available port")
	return 0
}

func waitPortListen(t *testing.T, port Port) {
	target := fmt.Sprintf("localhost:%d", port)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", target, time.Second)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Port %d didn't open", port)
}

func genTempFilePath() string {
	tempDir := os.TempDir()
	fname := fmt.Sprintf("wwwhisper-test-%d", time.Now().UnixNano())
	return filepath.Join(tempDir, fname)
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

	wwwhisperURL := parseURL(env.authServer.URL)
	wwwhisperURL.User = url.UserPassword(wwwhisperUsername, wwwhisperPassword)
	wwwhisperHandler := NewAuthHandler(wwwhisperURL, log, env.AppProxy)

	env.protectedAppServer = httptest.NewServer(wwwhisperHandler)
	env.ExternalURL = env.protectedAppServer.URL
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
	os.Unsetenv("WWWHISPER_LOG")
	os.Unsetenv("PORT")
	os.Unsetenv("PROXY_TO_PORT")
}

func TestCreateConfig(t *testing.T) {
	clearEnv()
	defer clearEnv()

	_, err := newConfig("")
	expected := "WWWHISPER_URL environment variable is not set"
	if err == nil || err.Error() != expected {
		t.Fatal("Unexpected error:", err)
	}

	os.Setenv("WWWHISPER_URL", "https://example.com:-1")
	_, err = newConfig("")
	expected = "WWWHISPER_URL has invalid format: "
	if err == nil || !strings.HasPrefix(err.Error(), expected) {
		t.Fatal("Unexpected error:", err)
	}

	os.Setenv("WWWHISPER_URL", "https://example.com")
	_, err = newConfig("")
	expected = "PORT environment variable is not set"
	if err == nil || err.Error() != expected {
		t.Fatal("Unexpected error:", err)
	}

	os.Setenv("PORT", "70000")
	_, err = newConfig("")
	expected = "PORT environment variable is invalid: port number out of range 70000"
	if err == nil || err.Error() != expected {
		t.Fatal("Unexpected error:", err)
	}

	os.Setenv("PORT", "5000")
	_, err = newConfig("")
	expected = "PROXY_TO_PORT environment variable is not set"
	if err == nil || err.Error() != expected {
		t.Fatal("Unexpected error:", err)
	}

	os.Setenv("PROXY_TO_PORT", "foo")
	_, err = newConfig("")
	expected = "PROXY_TO_PORT environment variable is invalid: failed to convert foo to port number"
	if err == nil || !strings.HasPrefix(err.Error(), expected) {
		t.Fatal("Unexpected error:", err)
	}

	os.Setenv("PROXY_TO_PORT", "999")
	cfg, _ := newConfig("/tmp/foo")

	if cfg.PidFilePath != "/tmp/foo" {
		t.Fatal("pidFilePath invalid", cfg.PidFilePath)
	}

	if cfg.WwwhisperURL.String() != "https://example.com" {
		t.Fatal("WwhisperURL invalid", cfg.WwwhisperURL)
	}

	if cfg.LogLevel != slog.LevelWarn {
		t.Fatal("LogLevel invalid", cfg.LogLevel)
	}
	if cfg.ExternalPort != 5000 {
		t.Fatal("ExternalPort invalid", cfg.ExternalPort)
	}
	if cfg.ProxyToPort != 999 {
		t.Fatal("ProxyToPort port invalid", cfg.ProxyToPort)
	}

	os.Setenv("WWWHISPER_LOG", "info")
	cfg, _ = newConfig("/tmp/foo")
	if cfg.LogLevel != slog.LevelInfo {
		t.Fatal("LogLevel invalid", cfg.LogLevel)
	}
}

func TestRunServerStartError(t *testing.T) {
	config := Config{
		WwwhisperURL: parseURL("https://wwwhisper.io"),
		// Should fail to bind
		ExternalPort: 1,
		ProxyToPort:  8000,
		LogLevel:     slog.LevelError,
	}
	err := Run(config)
	expected := "listen tcp"
	if !errors.Is(err, os.ErrPermission) ||
		!strings.Contains(err.Error(), expected) {
		t.Fatal("Unexpected error:", err)
	}
}

func TestSignalTermination(t *testing.T) {
	config := Config{
		WwwhisperURL: parseURL("https://wwwhisper.io"),
		ExternalPort: findPortToListen(t, 10000),
		ProxyToPort:  0,
		LogLevel:     slog.LevelError,
	}
	serverStatus := make(chan error, 1)

	go func() {
		serverStatus <- Run(config)
	}()
	// Wait for the server to start accepting connections because then
	// the signal handler is for sure registered.
	waitPortListen(t, config.ExternalPort)

	process, _ := os.FindProcess(os.Getpid())
	process.Signal(syscall.SIGTERM)

	err := <-serverStatus
	if err != nil {
		t.Fatal("Unexpected error", err)
	}
}

func TestPidFile(t *testing.T) {
	serverStatus := make(chan error, 1)
	config := Config{
		PidFilePath:  genTempFilePath(),
		WwwhisperURL: parseURL("https://wwwhisper.io"),
		ExternalPort: findPortToListen(t, 10000),
		ProxyToPort:  0,
		LogLevel:     slog.LevelError,
	}

	go func() {
		serverStatus <- Run(config)
	}()
	waitPortListen(t, config.ExternalPort)

	pidFileContent, err := ioutil.ReadFile(config.PidFilePath)
	if err != nil {
		t.Fatal("Error reading pid file")
	}
	pidStr := strings.TrimSpace(string(pidFileContent))
	pid, _ := strconv.Atoi(pidStr)
	if pid != os.Getpid() {
		t.Fatal("Pid file content invalid: ", pid)
	}

	process, _ := os.FindProcess(pid)
	process.Signal(syscall.SIGTERM)

	err = <-serverStatus
	if err != nil {
		t.Fatal("Unexpected error", err)
	}

	_, err = ioutil.ReadFile(config.PidFilePath)
	if !os.IsNotExist(err) {
		t.Fatal("Pid file not removed", err)
	}
}

func TestPidFileCreationError(t *testing.T) {
	config := Config{
		// Pass not writable file as the pid file path
		PidFilePath:  "/proc/uptime",
		WwwhisperURL: parseURL("https://wwwhisper.io"),
		ExternalPort: 0,
		ProxyToPort:  0,
		LogLevel:     slog.LevelError,
	}

	err := Run(config)
	if !strings.HasPrefix(err.Error(), "Error writing PID file:") {
		t.Fatal("Pid file creation error not returned", err)
	}
}

func TestAppRequestAllowed(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		siteURL := req.Header.Get("Site-Url")
		if siteURL != testEnv.ExternalURL {
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

	resp, err := http.Get(testEnv.ExternalURL + "/hello")
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

	resp, err := http.Get(testEnv.ExternalURL + "/foobar")
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

	resp, err := http.Get(testEnv.ExternalURL + "/wwwhisper/auth/login")
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

	resp, err := http.Get(testEnv.ExternalURL + "/foo")
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
			resp, err := http.Get(testEnv.ExternalURL + test.path_in)
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
		if siteURL != testEnv.ExternalURL {
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

	resp, err := http.Get(testEnv.ExternalURL + "/wwwhisper/admin/x?foo=bar")
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
		if siteURL != testEnv.ExternalURL {
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

	postURL := testEnv.ExternalURL + "/wwwhisper/admin/submit"
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
	req, _ := http.NewRequest("GET", testEnv.ExternalURL, nil)
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
	req, _ = http.NewRequest("GET", testEnv.ExternalURL+"/wwwhisper/admin/", nil)
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
	req, _ := http.NewRequest("GET", testEnv.ExternalURL+"/foobar", nil)
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
	resp, err := http.Get(testEnv.ExternalURL + "/foo")
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
	resp, err = http.Get(testEnv.ExternalURL + "/foo")
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
	resp, err = http.Get(testEnv.ExternalURL + "/foo")
	assertResponse(t, resp, err, 200, &responseUnmodified)

	// Iframe should not be injected HTML responses without the closing </body> tag.
	responseNoBody := "<html><head>foo</head></html>"
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(responseNoBody))
	}
	resp, err = http.Get(testEnv.ExternalURL + "/foo")
	assertResponse(t, resp, err, 200, &responseNoBody)

	// Iframe should not be injected wwwhisper backend responses.
	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Content-Type", "text/html")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(responseUnmodified))
	}
	resp, err = http.Get(testEnv.ExternalURL + "/wwwhisper/admin")
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
	resp, err := http.Get(testEnv.ExternalURL + "/foo")
	assertResponse(t, resp, err, 502, &expectedBody)
}

func TestStringToPort(t *testing.T) {
	_, err := parsePort("foo")
	expected := "failed to convert foo to port number: "
	if !strings.HasPrefix(err.Error(), expected) {
		t.Error("Unexpected output", err)
	}

	_, err = parsePort("65536")
	expected = "port number out of range 65536"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Error("Unexpected output", err)
	}

	_, err = parsePort("-1")
	expected = "port number out of range -1"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Error("Unexpected output", err)
	}

	port, err := parsePort("0")
	if port != 0 || err != nil {
		t.Error("Unexpected output", port, err)
	}

	port, err = parsePort("65535")
	if port != 65535 || err != nil {
		t.Error("Unexpected output", port, err)
	}
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
			out := parseLogLevel(test.level_in)
			if test.level_out != out {
				t.Errorf("expected: %s, got: %s", test.level_out, out)
			}
		})
	}
}
