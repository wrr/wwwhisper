package main

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

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

		newReq, err := http.NewRequestWithContext(
			r.Context(),
			r.Method,
			targetURL.String(),
			r.Body,
		)
		if err != nil {
			http.Error(w, "Error creating request to app: "+err.Error(), http.StatusInternalServerError)
			return
		}

		for key, values := range r.Header {
			for _, value := range values {
				newReq.Header.Add(key, value)
			}
		}

		resp, err := client.Do(newReq)
		if err != nil {
			http.Error(w, "Error making request to app: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		w.WriteHeader(resp.StatusCode)

		if _, err := io.Copy(w, resp.Body); err != nil {
			log.Error("Error copying response", "error", err)
		}
	})
}

func WWWhisper(wwwhisperURL string, log *slog.Logger, h http.Handler) http.Handler {
	authPath := "/wwwhisper/auth/api/is-authorized/"
	// TODO: OK to reuse?
	client := &http.Client{}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: cleanup logs
		log.Info("request IP", "path", r.URL.Path, "ip", r.RemoteAddr)
		var requestURL, requestMethod string
		handledByWWWhisper := false
		var bodyReader io.Reader
		if strings.HasPrefix(r.URL.Path, "/wwwhisper/auth/") {
			requestURL = wwwhisperURL + r.URL.Path
			requestMethod = r.Method
			handledByWWWhisper = true
			if requestMethod == "POST" || requestMethod == "PUT" {
				bodyBytes, err := io.ReadAll(r.Body)
				// TODO: polish error handling
				if err != nil {
					log.Error("Error reading request body", "error", err)
					http.Error(w, "Unable to read request body", http.StatusBadRequest)
					return
				}
				r.Body.Close()
				bodyReader = bytes.NewReader(bodyBytes)
			}
		} else {
			requestURL = wwwhisperURL + authPath + "?path=" + r.URL.Path
			requestMethod = "GET"
		}
		log.Info("Subrequest", "method", requestMethod, "url", requestURL)
		// TODO: rename req sub_req
		req, err := http.NewRequest(requestMethod, requestURL, bodyReader)
		if err != nil {
			// TODO: messages, ':' needed?
			log.Error("Error creating request:", "error", err)
			return
		}
		// TODO: do not copy all?
		for key, values := range r.Header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
		req.Header.Set("Site-Url", "http://localhost:8080")
		resp, err := client.Do(req)
		if err != nil {
			log.Error("auth request error:", "error", err)
			return
		}
		defer resp.Body.Close()
		if !handledByWWWhisper {
			if resp.StatusCode == http.StatusOK {
				log.Info("Access granted")
				h.ServeHTTP(w, r)
				return
			}
			log.Info("Access denied")
		}

		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
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
