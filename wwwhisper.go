package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

func copyRequestHeaders(src *http.Request, dst *http.Request) {
	for key, values := range src.Header {
		for _, value := range values {
			dst.Header.Add(key, value)
		}
	}
}

func copyResponse(resp *http.Response, w http.ResponseWriter) error {
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err := io.Copy(w, resp.Body)
	return err
}

func ProxyHandler(dstURL string, log *slog.Logger) http.Handler {
	client := &http.Client{}
	parts := strings.SplitN(dstURL, "://", 2)
	if len(parts) != 2 {
		// TODO: nicer error handling
		panic("Scheme missing in the app URL")
	}
	dstScheme := parts[0]
	dstHost := parts[1]

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetURL := *r.URL

		// TODO: parse scheme from the host
		targetURL.Host = dstHost
		targetURL.Scheme = dstScheme

		subReq, err := http.NewRequestWithContext(
			r.Context(),
			r.Method,
			targetURL.String(),
			r.Body,
		)
		if err != nil {
			http.Error(w, "Error creating request to app: "+err.Error(), http.StatusInternalServerError)
			return
		}

		copyRequestHeaders(r, subReq)

		resp, err := client.Do(subReq)
		if err != nil {
			http.Error(w, "Error making request to app: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		err = copyResponse(resp, w)
		if err != nil {
			// TODO: veify and comment - can't return a response because headers were already written.
			log.Error("Error copying proxied response", "error", err)
		}
	})
}

func WWWhisper(wwwhisperURL string, log *slog.Logger, h http.Handler) http.Handler {
	authURL := wwwhisperURL + "/wwwhisper/auth/api/is-authorized/"
	// TODO: OK to reuse?
	client := &http.Client{}
	wwwhisperHandler := ProxyHandler(wwwhisperURL, log)

	makeAuthRequest := func(r *http.Request) (*http.Response, error) {
		// TODO: which path
		authReq, err := http.NewRequest("GET", authURL+"?path="+r.URL.Path, nil)
		if err != nil {
			return nil, err
		}
		copyRequestHeaders(r, authReq)
		// TODO: Site-Url and tests
		authReq.Header.Set("Site-Url", "http://localhost:8080")
		return client.Do(authReq)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: cleanup logs
		log.Info("wwwhisper request", "path", r.URL.Path)
		if strings.HasPrefix(r.URL.Path, "/wwwhisper/auth/") {
			wwwhisperHandler.ServeHTTP(w, r)
			return
		}
		authResp, err := makeAuthRequest(r)
		if err != nil {
			// TODO: messages, ':' needed?
			log.Error("auth request error:", "error", err)
			http.Error(w, "Auth request error:"+err.Error(), http.StatusInternalServerError)
			return
		}
		defer authResp.Body.Close()
		if authResp.StatusCode == http.StatusOK {
			log.Info("Access granted")
			h.ServeHTTP(w, r)
			return
		}
		log.Info("Access denied")

		err = copyResponse(authResp, w)
		if err != nil {
			log.Error("Error copying auth response", "error", err)
		}
	})
}

func die(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}

func main() {
	wwwhisperURL := os.Getenv("WWWHISPER_URL")
	if wwwhisperURL == "" {
		die("WWWHISPER_URL environment variable is not set")
	}

	appPort := os.Getenv("APP_PORT")
	if appPort == "" {
		die("APP_PORT environment variable is not set")
	}
	dstURL := "http://localhost:" + appPort

	mux := http.NewServeMux()
	// TODO: tune timeouts
	s := http.Server{
		Addr:         ":8080",
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 20 * time.Second,
		Handler:      mux,
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{})
	log := slog.New(handler)
	mux.Handle("/", WWWhisper(wwwhisperURL, log, ProxyHandler(dstURL, log)))

	err := s.ListenAndServe()
	if err != nil {
		if err != http.ErrServerClosed {
			panic(err)
		}
	}
}
