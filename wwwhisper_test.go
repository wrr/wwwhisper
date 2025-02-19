package main

import (
	"io/ioutil"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type TestEnv struct {
	ProtectedUrl       string
	appServer          *httptest.Server
	wwwhisperServer    *httptest.Server
	protectedAppServer *httptest.Server
	AuthCount          int
}

func (env *TestEnv) dispose() {
	defer env.appServer.Close()
	defer env.wwwhisperServer.Close()
	defer env.protectedAppServer.Close()
}

func newTestEnv() *TestEnv {
	var env TestEnv
	env.appServer = httptest.NewServer(
		http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.Write([]byte("Hello world"))
		}))
	env.wwwhisperServer = httptest.NewServer(
		http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			env.AuthCount++
			rw.Write([]byte("allowed"))
		}))

	options := &slog.HandlerOptions{}
	handler := slog.NewTextHandler(os.Stderr, options)
	log := slog.New(handler)

	env.protectedAppServer = httptest.NewServer(
		WWWhisper(env.wwwhisperServer.URL, log, ProxyHandler(env.appServer.URL, log)))
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

	resp, err := http.Get(testEnv.ProtectedUrl)
	expectedBody := "Hello world"
	assertResponse(t, resp, err, http.StatusOK, &expectedBody)
	if testEnv.AuthCount != 1 {
		t.Fatal("Auth request not made")
	}
}
