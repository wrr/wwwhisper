package main

import (
	"io"
	"io/ioutil"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

func newTestEnv() *TestEnv {
	var env TestEnv
	env.AppHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("Hello world"))
	}
	env.appServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		env.AppCount++
		env.AppHandler(rw, req)
	}))
	env.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("allowed"))
	}
	env.authServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		env.AuthCount++
		env.AuthHandler(rw, req)
	}))

	options := &slog.HandlerOptions{}
	handler := slog.NewTextHandler(io.Discard, options)
	log := slog.New(handler)

	env.protectedAppServer = httptest.NewServer(
		WWWhisper(env.authServer.URL, log, ProxyHandler(env.appServer.URL, log)))
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
			t.Fatalf("Expected body %s; got %s", *expectedBody, string(body))
		}
	}
}

func TestAppRequestAllowed(t *testing.T) {
	testEnv := newTestEnv()
	defer testEnv.dispose()

	testEnv.AuthHandler = func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/wwwhisper/auth/api/is-authorized/" {
			t.Fatal("Invalid auth request path", req.URL.Path)
		}
		queryArg := req.URL.Query().Get("path")
		if queryArg == "" || queryArg != "/hello" {
			t.Fatal("Auth request argument invalid", queryArg)
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
