package main

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
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
	AppServer  *httptest.Server
	AppHandler func(http.ResponseWriter, *http.Request)
	AppCount   int

	AuthServer  *httptest.Server
	AuthHandler func(http.ResponseWriter, *http.Request)
	AuthCount   int

	ExternalURL        string
	ProtectedAppServer *httptest.Server

	AppProxy *httputil.ReverseProxy
}

func (env *TestEnv) dispose() {
	defer env.AppServer.Close()
	defer env.AuthServer.Close()
	defer env.ProtectedAppServer.Close()
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
	t.Helper()
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
	t.Helper()
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
	t.Helper()
	var env TestEnv
	env.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("Hello world"))
	}
	env.AppServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		env.AppHandler(rw, req)
		env.AppCount++
	}))
	env.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("allowed"))
	}
	env.AuthServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
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

	appUrlParsed, _ := url.Parse(env.AppServer.URL)
	env.AppProxy = NewReverseProxy(appUrlParsed, log, false, false)

	wwwhisperURL := parseURL(env.AuthServer.URL)
	wwwhisperURL.User = url.UserPassword(wwwhisperUsername, wwwhisperPassword)
	wwwhisperHandler := NewAuthHandler(wwwhisperURL, log, env.AppProxy)

	env.ProtectedAppServer = httptest.NewServer(wwwhisperHandler)
	env.ExternalURL = env.ProtectedAppServer.URL
	return &env
}

func checkResponse(resp *http.Response, err error, expectedStatus int, expectedBody *string) error {
	if err != nil {
		return fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != expectedStatus {
		return fmt.Errorf("expected status %v; got %v", expectedStatus, resp.StatusCode)
	}

	if expectedBody != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		if string(body) != *expectedBody {
			return fmt.Errorf("expected body '%s'; got '%s'", *expectedBody, string(body))
		}
	}
	return nil
}

func clearEnv() {
	os.Unsetenv("WWWHISPER_URL")
	os.Unsetenv("WWWHISPER_LOG")
	os.Unsetenv("WWWHISPER_NO_OVERLAY")
}

func TestNewConfig(t *testing.T) {
	clearEnv()
	defer clearEnv()

	_, err := newConfig("", 80, 8080)
	expected := "WWWHISPER_URL environment variable is not set"
	if err == nil || err.Error() != expected {
		t.Error("Unexpected error:", err)
	}

	os.Setenv("WWWHISPER_URL", "https://example.com:-1")
	_, err = newConfig("", 80, 8080)
	expected = "WWWHISPER_URL has invalid format: "
	if err == nil || !strings.HasPrefix(err.Error(), expected) {
		t.Error("Unexpected error:", err)
	}

	os.Setenv("WWWHISPER_URL", "https://example.com")
	_, err = newConfig("", 70000, 8080)
	expected = "port number out of range 70000"
	if err == nil || err.Error() != expected {
		t.Error("Unexpected error:", err)
	}

	_, err = newConfig("", 80, 80000)
	expected = "port number out of range 80000"
	if err == nil || !strings.HasPrefix(err.Error(), expected) {
		t.Error("Unexpected error:", err)
	}

	cfg, _ := newConfig("/tmp/foo", 80, 8080)
	if cfg.PidFilePath != "/tmp/foo" {
		t.Error("pidFilePath invalid", cfg.PidFilePath)
	}
	if cfg.NoOverlay != false {
		t.Error("NoOverlay invalid")
	}
	if cfg.WwwhisperURL.String() != "https://example.com" {
		t.Error("WwhisperURL invalid", cfg.WwwhisperURL)
	}
	if cfg.LogLevel != slog.LevelWarn {
		t.Error("LogLevel invalid", cfg.LogLevel)
	}
	if cfg.Listen != 80 {
		t.Error("ExternalPort invalid", cfg.Listen)
	}
	if cfg.ProxyTo != 8080 {
		t.Error("ProxyToPort port invalid", cfg.ProxyTo)
	}

	os.Setenv("WWWHISPER_LOG", "info")
	os.Setenv("WWWHISPER_NO_OVERLAY", "")
	cfg, _ = newConfig("/tmp/foo", 80, 8080)
	if cfg.LogLevel != slog.LevelInfo {
		t.Error("LogLevel invalid", cfg.LogLevel)
	}
	if cfg.NoOverlay != true {
		t.Error("NoOverlay invalid")
	}
}

func TestRunServerStartError(t *testing.T) {
	config := Config{
		WwwhisperURL: parseURL("https://wwwhisper.io"),
		// Should fail to bind
		Listen:   1,
		ProxyTo:  8000,
		LogLevel: slog.LevelError,
	}
	err := Run(config)
	expected := "listen tcp"
	if !errors.Is(err, os.ErrPermission) ||
		!strings.Contains(err.Error(), expected) {
		t.Error("Unexpected error:", err)
	}
}

func TestSignalTermination(t *testing.T) {
	config := Config{
		WwwhisperURL: parseURL("https://wwwhisper.io"),
		Listen:       findPortToListen(t, 10000),
		ProxyTo:      0,
		LogLevel:     slog.LevelError,
	}
	serverStatus := make(chan error, 1)

	go func() {
		serverStatus <- Run(config)
	}()
	// Wait for the server to start accepting connections because then
	// the signal handler is for sure registered.
	waitPortListen(t, config.Listen)

	process, _ := os.FindProcess(os.Getpid())
	process.Signal(syscall.SIGTERM)

	err := <-serverStatus
	if err != nil {
		t.Error("Unexpected error", err)
	}
}

func TestPidFile(t *testing.T) {
	serverStatus := make(chan error, 1)
	config := Config{
		PidFilePath:  genTempFilePath(),
		WwwhisperURL: parseURL("https://wwwhisper.io"),
		Listen:       findPortToListen(t, 10000),
		ProxyTo:      0,
		LogLevel:     slog.LevelError,
	}

	go func() {
		serverStatus <- Run(config)
	}()
	waitPortListen(t, config.Listen)

	pidFileContent, err := os.ReadFile(config.PidFilePath)
	if err != nil {
		t.Fatal("Error reading pid file")
	}
	pidStr := strings.TrimSpace(string(pidFileContent))
	pid, _ := strconv.Atoi(pidStr)
	if pid != os.Getpid() {
		t.Error("Pid file content invalid: ", pid)
	}

	process, _ := os.FindProcess(pid)
	process.Signal(syscall.SIGTERM)

	err = <-serverStatus
	if err != nil {
		t.Error("Unexpected error", err)
	}

	_, err = os.ReadFile(config.PidFilePath)
	if !os.IsNotExist(err) {
		t.Error("Pid file not removed", err)
	}
}

func TestPidFileCreationError(t *testing.T) {
	config := Config{
		// Pass not writable file as the pid file path
		PidFilePath:  "/proc/uptime",
		WwwhisperURL: parseURL("https://wwwhisper.io"),
		Listen:       0,
		ProxyTo:      0,
		LogLevel:     slog.LevelError,
	}

	err := Run(config)
	if !strings.HasPrefix(err.Error(), "error writing PID file:") {
		t.Error("Pid file creation error not returned", err)
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
		cookies := req.Header.Get("Cookie")
		if cookies != "foo=1; bar=xyz" {
			t.Error("Invalid cookies", cookies)
			return
		}
		accept := req.Header.Get("Accept")
		if accept != "application/custom" {
			t.Error("Invalid Accept header", accept)
			return
		}
		custom := req.Header.Get("X-Custom")
		if custom != "" {
			t.Error("X-Custom header not removed", custom)
			return
		}
		if req.URL.RequestURI() != authQuery("/hello") {
			// No t.Fatal, because it can be called only in the main test
			// function go routine.
			t.Error("Invalid auth request URI", req.URL.RequestURI())
			return
		}
		rw.Write([]byte("allowed"))
	}
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		proto := req.Header.Get("X-Forwarded-Proto")
		if proto != "http" {
			t.Error("Invalid X-Forwarded-Proto", proto)
			return
		}
		rw.Write([]byte("hello"))
	}

	req, _ := http.NewRequest("GET", testEnv.ExternalURL+"/hello", nil)
	req.Header.Add("Accept", "application/custom")
	req.Header.Add("Cookie", "foo=1; bar=xyz")
	req.Header.Add("Site-Url", "https://should.be.changed")
	req.Header.Add("X-Custom", "should be removed")
	req.Header.Add("X-Forwarded-Proto", "http")
	client := &http.Client{}
	resp, err := client.Do(req)

	expectedBody := "hello"
	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if testEnv.AuthCount != 1 {
		t.Error("Auth request not made")
	}
	if testEnv.AppCount != 1 {
		t.Error("App request not made")
	}
}

func TestSiteUrlProto(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		siteURL := req.Header.Get("Site-Url")
		if strings.HasSuffix(siteURL, "https://") {
			t.Error("Site-Url header invalid protocol")
			return
		}
	}

	req, _ := http.NewRequest("GET", testEnv.ExternalURL+"/hello", nil)
	req.Header.Add("X-Forwarded-Proto", "https")
	client := &http.Client{}
	client.Do(req)
	if testEnv.AuthCount != 1 {
		t.Error("Auth request not made")
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
	if err = checkResponse(resp, err, http.StatusUnauthorized, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if testEnv.AuthCount != 1 {
		t.Error("Auth request not made")
	}
	if testEnv.AppCount != 0 {
		t.Error("App request made")
	}
}

func TestAuthBackendNotNeededResponseHeadersStripped(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()
	authReturn := http.StatusUnauthorized

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Via", "test-router")
		rw.Header().Add("Nel", "x")
		rw.Header().Add("Report-To", "y")
		rw.Header().Add("Reporting-Endpoints", "z")
		rw.Header().Add("User", "alice@example.com")
		rw.WriteHeader(authReturn)
	}

	// Test two cases:
	// 1) when access is denied, not needed headers are stripped from the
	//    is-authorized response that returns access denied
	// 2) when access is allowed, not neeeded headers are stripped from the
	//    /wwwhisper/admin response
	for i := 0; i < 2; i += 1 {
		resp, err := http.Get(testEnv.ExternalURL + "/wwwhisper/admin")
		expectedBody := ""
		if err = checkResponse(resp, err, authReturn, &expectedBody); err != nil {
			t.Error("Invalid response", err)
		}
		headers := []string{"Via", "Nel", "Report-To", "Reporting-Endpoints", "User"}
		for _, h := range headers {
			if resp.Header.Get(h) != "" {
				t.Error("Header not stripped:", h)
			}
		}
		authReturn = http.StatusOK
	}

	if testEnv.AuthCount != 3 {
		t.Error("Auth requests not made")
	}
}

func TestUserHeaderPassedToApp(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("User", "alice@example.org")
		rw.WriteHeader(200)
		rw.Write([]byte("allowed"))
	}
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		user := strings.Join(req.Header.Values("User"), "; ")
		if user != "alice@example.org" {
			t.Error("Invalid User header", user)
		}
		rw.Write([]byte("hello"))
	}

	req, _ := http.NewRequest("GET", testEnv.ExternalURL+"/hello", nil)
	// User header that comes from the client should be dropped.
	req.Header.Add("User", "eve@example.com")
	client := &http.Client{}
	resp, err := client.Do(req)
	expectedBody := "hello"
	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if testEnv.AppCount != 1 {
		t.Error("App request not made")
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
	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if testEnv.AuthCount != 1 {
		t.Error("Auth request not made")
	}
	if testEnv.AppCount != 0 {
		t.Error("App request made")
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
	expectedBody := "Internal server error (auth)\n"
	if err = checkResponse(resp, err, 500, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}

	if testEnv.AuthCount != 1 {
		t.Error("Auth request not made")
	}
	if testEnv.AppCount != 0 {
		t.Error("App request made")
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
		if req.Host != parseURL(testEnv.ExternalURL).Host {
			t.Error("Invalid Host header", req.Host, testEnv.ExternalURL)
		}

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
			if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
				t.Error("Invalid response", err)
			}
		})
	}
}

func TestAdminPathAllowed(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		if req.Host != parseURL(testEnv.AuthServer.URL).Host {
			t.Error("Invalid Host header", req.Host, testEnv.AuthServer.URL)
		}

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
	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if testEnv.AuthCount != 2 {
		t.Error("Auth requests not made")
	}
	if testEnv.AppCount != 0 {
		t.Error("App request made")
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
	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if testEnv.AuthCount != 2 {
		t.Error("Auth requests not made")
	}
	if testEnv.AppCount != 0 {
		t.Error("App request made")
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
		if req.Header.Get("Site-Url") != "" {
			t.Error("Site-Url header passed to the app")
		}
		rw.Write([]byte("hello"))
	}
	req, _ := http.NewRequest("GET", testEnv.ExternalURL, nil)
	req.Header.Set("User-Agent", "test-agent")
	client := &http.Client{}
	resp, err := client.Do(req)
	expectedBody := "hello"

	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if testEnv.AuthCount != 1 {
		t.Error("Auth request not made")
	}
	if testEnv.AppCount != 1 {
		t.Error("App request not made")
	}

	// /wwwhisper/admin requests should also carry the original User Agent
	req, _ = http.NewRequest("GET", testEnv.ExternalURL+"/wwwhisper/admin/", nil)
	req.Header.Set("User-Agent", "test-agent")
	resp, err = client.Do(req)
	expectedBody = "auth response"
	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if testEnv.AuthCount != 3 {
		t.Error("Auth requests not made")
	}
	if testEnv.AppCount != 1 {
		t.Error("App request  made")
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
	if err = checkResponse(resp, err, 302, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	location := resp.Header.Get("location")
	if location != "https://localhost:9999/foo/bar" {
		t.Error("Location header not returned to client", location)
	}
	if testEnv.AuthCount != 1 {
		t.Error("Auth request not made")
	}
	if testEnv.AppCount != 1 {
		t.Error("App request not made")
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
	if err = checkResponse(resp, err, 200, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}

	// Iframe should not be injected to not HTML responses
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(responseUnmodified))
	}
	resp, err = http.Get(testEnv.ExternalURL + "/foo")
	if err = checkResponse(resp, err, 200, &responseUnmodified); err != nil {
		t.Error("Invalid response", err)
	}

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
	if err = checkResponse(resp, err, 200, &responseUnmodified); err != nil {
		t.Error("Invalid response", err)
	}

	// Iframe should not be injected HTML responses without the closing </body> tag.
	responseNoBody := "<html><head>foo</head></html>"
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(responseNoBody))
	}
	resp, err = http.Get(testEnv.ExternalURL + "/foo")
	if err = checkResponse(resp, err, 200, &responseNoBody); err != nil {
		t.Error("Invalid response", err)
	}

	// Iframe should not be injected wwwhisper backend responses.
	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Content-Type", "text/html")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(responseUnmodified))
	}
	resp, err = http.Get(testEnv.ExternalURL + "/wwwhisper/admin")
	if err = checkResponse(resp, err, 200, &responseUnmodified); err != nil {
		t.Error("Invalid response", err)
	}
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
	if err = checkResponse(resp, err, 502, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
}

func TestIntToPort(t *testing.T) {
	_, err := intToPort(65536)
	expected := "port number out of range 65536"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Error("Unexpected output", err)
	}

	_, err = intToPort(-1)
	expected = "port number out of range -1"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Error("Unexpected output", err)
	}

	port, err := intToPort(0)
	if port != 0 || err != nil {
		t.Error("Unexpected output", port, err)
	}

	port, err = intToPort(65535)
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
