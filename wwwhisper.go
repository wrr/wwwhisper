package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func copyRequestHeaders(dst *http.Request, src *http.Request) {
	for key, values := range src.Header {
		for _, value := range values {
			dst.Header.Add(key, value)
		}
	}
}

func copyResponse(w http.ResponseWriter, src *http.Response) error {
	for key, values := range src.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(src.StatusCode)
	_, err := io.Copy(w, src.Body)
	return err
}

func serverError(log *slog.Logger, w http.ResponseWriter, msg string, err error) {
	msg = "Internal server error: " + msg
	log.Error(msg + "; " + err.Error())
	// Do not return err.Error() to the user as it can contain sensitive
	// data.
	http.Error(w, msg, http.StatusInternalServerError)
}

func ProxyHandler(dstUrlStr string, log *slog.Logger) http.Handler {
	client := &http.Client{}
	dstUrl, err := url.Parse(dstUrlStr)
	if err != nil {
		// TODO: nicer error reporting
		panic("Error parsing " + dstUrlStr)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetURL := *r.URL

		targetURL.Scheme = dstUrl.Scheme
		targetURL.User = dstUrl.User
		targetURL.Host = dstUrl.Host

		subReq, err := http.NewRequestWithContext(
			r.Context(),
			r.Method,
			targetURL.String(),
			r.Body,
		)
		if err != nil {
			serverError(log, w, "app request creation", err)
			return
		}

		copyRequestHeaders(subReq, r)

		resp, err := client.Do(subReq)
		if err != nil {
			serverError(log, w, "app request", err)
			return
		}
		defer resp.Body.Close()

		err = copyResponse(w, resp)
		if err != nil {
			// TODO: veify and comment - can't return a response because headers were already written.
			log.Error("Error copying proxied response: " + err.Error())
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
		copyRequestHeaders(authReq, r)
		// TODO: Site-Url and tests
		authReq.Header.Set("Site-Url", "http://localhost:8080")
		return client.Do(authReq)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: cleanup logs
		log.Info("wwwhisper request", "path", r.URL.Path)
		if strings.HasPrefix(r.URL.Path, "/wwwhisper/auth/") {
			// login/logout/send-token etc. always allowed, doesn't require authorization.
			wwwhisperHandler.ServeHTTP(w, r)
			return
		}
		authResp, err := makeAuthRequest(r)
		if err != nil {
			serverError(log, w, "auth request", err)
			return
		}
		defer authResp.Body.Close()
		if authResp.StatusCode != http.StatusOK {
			log.Info("Access denied")
			err = copyResponse(w, authResp)
			if err != nil {
				log.Error("Error copying auth response: " + err.Error())
			}
			return
		}

		log.Info("Access granted")
		if strings.HasPrefix(r.URL.Path, "/wwwhisper/") {
			wwwhisperHandler.ServeHTTP(w, r)
		} else {
			h.ServeHTTP(w, r)
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
