package proxy

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
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/wrr/wwwhispergo/internal/proxytest"
)

type TestEnv struct {
	AppServer  *httptest.Server
	AppHandler func(http.ResponseWriter, *http.Request)
	appCount   atomic.Int32

	AuthServer *proxytest.AuthServer

	ExternalURL        string
	ProtectedAppServer *httptest.Server

	AppProxy *httputil.ReverseProxy

	Client *http.Client
}

func (env *TestEnv) AppCount() int32 {
	return env.appCount.Load()
}

func (env *TestEnv) dispose() {
	defer env.AppServer.Close()
	defer env.AuthServer.Close()
	defer env.ProtectedAppServer.Close()
}

func newTestEnv(t *testing.T) *TestEnv {
	t.Helper()
	var env TestEnv
	env.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("Hello world"))
	}
	env.AppServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		env.AppHandler(rw, req)
		env.appCount.Add(1)
	}))
	env.AuthServer = proxytest.NewAuthServer(t)

	log := proxytest.NewLogger()

	appUrlParsed, _ := url.Parse(env.AppServer.URL)
	env.AppProxy = newReverseProxy(&reverseProxyConfig{
		target:           appUrlParsed,
		log:              log,
		proxyToWwwhisper: false,
		cachingStore:     nil,
		noOverlay:        false,
	})

	wwwhisperHandler := newRootHandler(env.AuthServer.URL, log, env.AppProxy)

	env.ProtectedAppServer = httptest.NewServer(wwwhisperHandler)
	env.ExternalURL = env.ProtectedAppServer.URL
	env.Client = &http.Client{}
	return &env
}

func parseURL(urlString string) *url.URL {
	result, _ := url.Parse(urlString)
	return result
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

func checkResponse(resp *http.Response, err error, expectedStatus int, expectedBody *string) error {
	if err != nil {
		return fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, bodyErr := io.ReadAll(resp.Body)
	body := ""
	if bodyErr == nil {
		body = string(bodyBytes)
	}

	if resp.StatusCode != expectedStatus {
		return fmt.Errorf("expected status %v; got %v %q", expectedStatus, resp.StatusCode, body)
	}

	if expectedBody != nil {
		if bodyErr != nil {
			return fmt.Errorf("failed to read response body: %v", bodyErr)
		}
		if body != *expectedBody {
			return fmt.Errorf("expected body %q; got %q", *expectedBody, body)
		}
	}
	return nil
}

func checkSecurityHeaders(resp *http.Response) error {
	headers := []struct {
		key   string
		value string
	}{
		{
			key:   "Cache-Control",
			value: cacheOff,
		},
		{
			key:   "X-Frame-Options",
			value: "SAMEORIGIN",
		},
		{
			key:   "X-Content-Type-Options",
			value: "nosniff",
		},
	}
	for _, h := range headers {
		if v := resp.Header.Get(h.key); v != h.value {
			return fmt.Errorf("%s header expected %q; got %q", h.key, h.value, v)
		}
	}
	return nil
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
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		proto := req.Header.Get("X-Forwarded-Proto")
		if proto != "http" {
			t.Error("Invalid X-Forwarded-Proto", proto)
			return
		}
		rw.Write([]byte("hello"))
	}

	req, _ := http.NewRequest("GET", testEnv.ExternalURL+"/hello", nil)
	req.Header.Add("Cookie", "wwwhisper-sessionid=alice-cookie")
	req.Header.Add("X-Forwarded-Proto", "http")
	resp, err := testEnv.Client.Do(req)

	expectedBody := "hello"
	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
}

func TestForbiddenIfNoRootLocation(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	// Replace location entry for the root path "/". If there is no root
	// location, some requests will not have a matching path, such
	// requests should be forbidden.
	testEnv.AuthServer.Locations[0].Path = "/foobar"

	resp, err := http.Get(testEnv.ExternalURL + "/foo")
	expectedBody := "Access forbidden."
	if err = checkResponse(resp, err, http.StatusForbidden, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if testEnv.AppCount() != 0 {
		t.Error("App request made")
	}
}

func TestSiteUrl(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	mux := testEnv.AuthServer.Mux
	mux.HandleFunc("/wwwhisper/auth/custom", func(rw http.ResponseWriter, req *http.Request) {
		siteURL := req.Header.Get("Site-Url")
		if strings.HasSuffix(siteURL, "https://") {
			t.Error("Site-Url header invalid protocol")
		}
		siteUrlNoProto := siteURL[8:]
		expectedUrlNoProto := testEnv.ExternalURL[7:]
		if siteUrlNoProto != expectedUrlNoProto {
			t.Error("Site-Url invalid", siteUrlNoProto, expectedUrlNoProto)
		}
		rw.Write([]byte("custom page"))
	})

	req, _ := http.NewRequest("GET", testEnv.ExternalURL+"/wwwhisper/auth/custom", nil)
	req.Header.Add("X-Forwarded-Proto", "https")
	resp, err := testEnv.Client.Do(req)
	expectedBody := "custom page"
	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
}

func TestRequestLoginNeededAcceptText(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	resp, err := http.Get(testEnv.ExternalURL + "/hello")
	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/plain; charset=utf-8" {
		t.Error("Invalid content type", contentType)
	}
	expectedBody := "Authentication required."
	if err = checkResponse(resp, err, http.StatusUnauthorized, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if testEnv.AppCount() != 0 {
		t.Error("App request made")
	}
}

func TestRequestLoginNeededAcceptHtml(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	req, _ := http.NewRequest("GET", testEnv.ExternalURL+"/hello", nil)
	req.Header.Add("Accept", "text/html")
	resp, err := testEnv.Client.Do(req)
	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Error("Invalid content type", contentType)
	}
	expectedBody := testEnv.AuthServer.LoginNeeded
	if err = checkResponse(resp, err, http.StatusUnauthorized, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if err = checkSecurityHeaders(resp); err != nil {
		t.Error(err)
	}
	if testEnv.AppCount() != 0 {
		t.Error("App request made")
	}
}

func TestModIdHeaderCacheInvalidation(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	checkPage := func(expectedBody string) error {
		req, _ := http.NewRequest("GET", testEnv.ExternalURL+"/hello", nil)
		req.Header.Add("Accept", "text/html")
		resp, err := testEnv.Client.Do(req)
		return checkResponse(resp, err, http.StatusUnauthorized, &expectedBody)
	}

	origPage := testEnv.AuthServer.LoginNeeded

	if err := checkPage(origPage); err != nil {
		t.Error("Invalid login page", err)
	}

	// Modify the login page
	newPage := origPage + "modified"
	testEnv.AuthServer.LoginNeeded = newPage

	// Login page is modified, but the original page should still be cached and returned.
	if err := checkPage(origPage); err != nil {
		t.Error("Invalid login page", err)
	}

	// A request to /wwwhisper/auth/login should return modId, but the modId is
	// not yet changed, so should not cause cache invalidation.
	http.Get(testEnv.ExternalURL + "/wwwhisper/auth/login")
	if err := checkPage(origPage); err != nil {
		t.Error("Invalid login page", err)
	}

	// Finaly, change the ModId; request to /wwwhisper/auth/login should
	// return it, cause cache invalidation and new version of
	// the page should be fetched and returned.
	testEnv.AuthServer.ModId += 1
	http.Get(testEnv.ExternalURL + "/wwwhisper/auth/login")
	if err := checkPage(newPage); err != nil {
		t.Error("Invalid login page", err)
	}
}

func TestRequestForbiddenAcceptText(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	req, _ := http.NewRequest("POST", testEnv.ExternalURL+"/wwwhisper/admin/foo", nil)
	req.Header.Add("Cookie", "wwwhisper-sessionid=bob-cookie")
	resp, err := testEnv.Client.Do(req)

	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/plain; charset=utf-8" {
		t.Error("Invalid content type", contentType)
	}
	expectedBody := "Access forbidden."
	if err = checkResponse(resp, err, http.StatusForbidden, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if err = checkSecurityHeaders(resp); err != nil {
		t.Error(err)
	}
	if testEnv.AppCount() != 0 {
		t.Error("App request made")
	}
}

func TestRequestForbiddenAcceptHtml(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	req, _ := http.NewRequest("POST", testEnv.ExternalURL+"/wwwhisper/admin/foo", nil)
	req.Header.Add("Accept", "text/html")
	req.Header.Add("Cookie", "wwwhisper-sessionid=bob-cookie")
	resp, err := testEnv.Client.Do(req)

	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Error("Invalid content type", contentType)
	}
	expectedBody := testEnv.AuthServer.Forbidden
	if err = checkResponse(resp, err, http.StatusForbidden, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if err = checkSecurityHeaders(resp); err != nil {
		t.Error(err)
	}
	if testEnv.AppCount() != 0 {
		t.Error("App request made")
	}
}

func TestAuthBackendNotNeededResponseHeadersStripped(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	headers := []string{"Via", "Nel", "Report-To", "Reporting-Endpoints", "User", "X-Mod-Id"}

	mux := testEnv.AuthServer.Mux
	mux.HandleFunc("/wwwhisper/auth/custom", func(rw http.ResponseWriter, req *http.Request) {
		for _, h := range headers {
			rw.Header().Add(h, "header-value")
		}
		rw.Write([]byte("custom page"))
	})

	resp, err := http.Get(testEnv.ExternalURL + "/wwwhisper/auth/custom")
	expectedBody := "custom page"
	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	for _, h := range headers {
		if resp.Header.Get(h) != "" {
			t.Error("Header not stripped:", h)
		}
	}
}

func TestUserHeaderPassedToApp(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		user := strings.Join(req.Header.Values("User"), "; ")
		if user != "alice@example.com" {
			t.Error("Invalid User header", user)
		}
		rw.Write([]byte("hello"))
	}

	req, _ := http.NewRequest("GET", testEnv.ExternalURL+"/open", nil)
	// User header that comes from the client should be dropped.
	req.Header.Add("User", "eve@example.com")
	req.Header.Add("Cookie", "wwwhisper-sessionid=alice-cookie")
	resp, err := testEnv.Client.Do(req)

	expectedBody := "hello"
	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
}

func TestAuthPathAllowed(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	resp, err := http.Get(testEnv.ExternalURL + "/wwwhisper/auth/login")
	expectedBody := "login response"
	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if testEnv.AppCount() != 0 {
		t.Error("App request made")
	}
}

func TestAuthServerNonHttpError(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()
	testEnv.AuthServer.Close()

	// Not authenticated request, location retrieval should fail.
	resp, err := http.Get(testEnv.ExternalURL)
	expectedBody := "Internal server error (auth)"
	if err = checkResponse(resp, err, 500, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
	if err = checkSecurityHeaders(resp); err != nil {
		t.Error(err)
	}

	// Authenticated request, whoami retrieval should fail.
	req, _ := http.NewRequest("GET", testEnv.ExternalURL+"/open", nil)
	req.Header.Add("Cookie", "wwwhisper-sessionid=alice-cookie")
	resp, err = testEnv.Client.Do(req)
	if err = checkResponse(resp, err, 500, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}

	if testEnv.AppCount() != 0 {
		t.Error("App request made")
	}
}

func TestPathNormalization(t *testing.T) {
	testCases := []struct {
		pathIn  string
		pathOut string
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
	var expectedPath string
	testEnv := newTestEnv(t)
	defer testEnv.dispose()
	testEnv.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		if req.Host != parseURL(testEnv.ExternalURL).Host {
			t.Error("Invalid Host header", req.Host, testEnv.ExternalURL)
		}

		if req.URL.RequestURI() != expectedPath {
			t.Error("Invalid app request path", req.URL.RequestURI(), expectedPath)
			return
		}
		rw.Write([]byte("ok"))
	}

	for _, test := range testCases {
		t.Run("["+test.pathIn+"]", func(t *testing.T) {
			expectedPath = test.pathOut
			req, _ := http.NewRequest("GET", testEnv.ExternalURL+test.pathIn, nil)
			req.Header.Add("Cookie", "wwwhisper-sessionid=alice-cookie")
			req.Header.Add("X-Forwarded-Proto", "http")
			resp, err := testEnv.Client.Do(req)
			expectedBody := "ok"
			if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
				t.Error("Invalid response", err)
			}
		})
	}
}

func TestAdminPathAccess(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	url := testEnv.ExternalURL + "/wwwhisper/admin/?foo=bar"

	// no user
	resp, err := http.Get(url)
	expectedBody := "Authentication required."
	if err = checkResponse(resp, err, http.StatusUnauthorized, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}

	// no admin user
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Cookie", "wwwhisper-sessionid=bob-cookie")
	resp, err = testEnv.Client.Do(req)
	expectedBody = "Access forbidden."
	if err = checkResponse(resp, err, http.StatusForbidden, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}

	// Admin user
	req, _ = http.NewRequest("GET", url, nil)
	req.Header.Add("Cookie", "wwwhisper-sessionid=alice-cookie")
	resp, err = testEnv.Client.Do(req)
	expectedBody = testEnv.AuthServer.Admin
	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}

	if testEnv.AppCount() != 0 {
		t.Error("App request made")
	}
}

func TestAdminPostRequest(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	url := testEnv.ExternalURL + "/wwwhisper/admin/submit"

	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Add("Cookie", "wwwhisper-sessionid=alice-cookie")
	req.Header.Add("Site-Url", "https://should.be.changed")
	resp, err := testEnv.Client.Do(req)
	// Ensure Site-Url header is correctly passed with requests to /wwwhisper/*
	expectedBody := fmt.Sprintf("{siteUrl: %q}", testEnv.ExternalURL)
	if err = checkResponse(resp, err, http.StatusOK, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}

	if testEnv.AppCount() != 0 {
		t.Error("App request made")
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
	req, _ := http.NewRequest("GET", testEnv.ExternalURL+"/open", nil)
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
	if testEnv.AppCount() != 1 {
		t.Error("App request not made")
	}
}

func TestIframeInjection(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	responseOrig := "<html><body>foo</body></html>"
	responseNoBody := "<html><head>foo</head></html>"
	responseInjected := `<html><body>foo
<script src="/wwwhisper/auth/iframe.js"></script>
</body></html>`

	newHandler := func(contentType string, body string) http.HandlerFunc {
		return func(rw http.ResponseWriter, req *http.Request) {
			rw.Header().Add("Content-Type", contentType)
			rw.WriteHeader(http.StatusOK)
			rw.Write([]byte(body))
		}
	}

	tests := []struct {
		name         string
		handler      func(rw http.ResponseWriter, req *http.Request)
		path         string
		noAuth       bool
		expectedBody string
	}{
		{
			name:         "no injection if not authenticated",
			handler:      newHandler("text/html", responseOrig),
			path:         "/open/foo",
			noAuth:       true,
			expectedBody: responseOrig,
		},
		{
			name:         "inject if authenticated",
			handler:      newHandler("text/html", responseOrig),
			path:         "/open/foo/",
			expectedBody: responseInjected,
		},
		{
			name:         "no injection for non-HTML responses",
			handler:      newHandler("text/plain", responseOrig),
			path:         "/foo/",
			expectedBody: responseOrig,
		},
		{
			name: "no injection for gzipped HTML responses",
			handler: func(rw http.ResponseWriter, req *http.Request) {
				rw.Header().Add("Content-Type", "text/html")
				rw.Header().Add("Content-Encoding", "gzip")
				rw.WriteHeader(http.StatusOK)
				gz := gzip.NewWriter(rw)
				defer gz.Close()
				gz.Write([]byte(responseOrig))
			},
			path:         "/foo/",
			expectedBody: responseOrig,
		},
		{
			name:         "no injection for HTML without closing body tag",
			handler:      newHandler("text/html", responseNoBody),
			path:         "/foo/",
			expectedBody: responseNoBody,
		},
		{
			name:         "no injection for wwwhisper backend responses",
			path:         "/wwwhisper/admin/",
			expectedBody: testEnv.AuthServer.Admin,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testEnv.AppHandler = tt.handler
			req, _ := http.NewRequest("GET", testEnv.ExternalURL+tt.path, nil)
			if !tt.noAuth {
				req.Header.Add("Cookie", "wwwhisper-sessionid=alice-cookie")
			}
			resp, err := testEnv.Client.Do(req)
			if err = checkResponse(resp, err, 200, &tt.expectedBody); err != nil {
				t.Errorf("Invalid response for %v", err)
			}
		})
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
	req, _ := http.NewRequest("GET", testEnv.ExternalURL+"/open/foo/", nil)
	req.Header.Add("Cookie", "wwwhisper-sessionid=alice-cookie")
	resp, err := testEnv.Client.Do(req)

	if err = checkResponse(resp, err, 502, &expectedBody); err != nil {
		t.Error("Invalid response", err)
	}
}
