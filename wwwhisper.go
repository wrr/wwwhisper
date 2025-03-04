package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

const Version string = "1.0.0"
const overlayToInject = `
<script src="/wwwhisper/auth/iframe.js"></script>
`

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

func setSiteURLHeader(dst *http.Request, incoming *http.Request) {
	scheme := incoming.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if incoming.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	dst.Header.Set("Site-Url", scheme+"://"+incoming.Host)
}

func encodeBasicAuth(username string, password string) string {
	toEncode := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(toEncode))
}

func getBasicAuthCredentials(url *url.URL) string {
	username := url.User.Username()
	password, is_password_set := url.User.Password()
	if !is_password_set {
		return ""
	}
	return encodeBasicAuth(username, password)
}

func injectOverlay(resp *http.Response) error {
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "text/html") ||
		resp.Header.Get("Content-Encoding") != "" {
		// Inject only to not compressed HTML responses.
		return nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	htmlString := string(bodyBytes)
	// Inject before the </body> tag
	tagIndex := strings.LastIndex(strings.ToLower(htmlString), "</body>")
	if tagIndex != -1 {
		htmlString = htmlString[:tagIndex] + overlayToInject + htmlString[tagIndex:]
	}

	bodyBytes = []byte(htmlString)
	resp.Header.Set("Content-Length", fmt.Sprint(len(bodyBytes)))
	resp.ContentLength = int64(len(bodyBytes))

	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return nil
}

func NewReverseProxy(target *url.URL, log *slog.Logger, proxyToWwwhisper bool) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	// TODO: convert log to log.Logger or maybe do not use slog at all?
	// proxy.ErrorLog = log
	credentials := getBasicAuthCredentials(target)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		if proxyToWwwhisper {
			setSiteURLHeader(req, req)
		}
		if credentials != "" {
			req.Header.Set("Authorization", credentials)
		}
		originalDirector(req)
	}

	// wwwhisper html responses already have the logout overlay added.
	if !proxyToWwwhisper {
		proxy.ModifyResponse = func(resp *http.Response) error {
			return injectOverlay(resp)
		}
	}
	return proxy
}

func normalize(url *url.URL) {
	path_in := url.Path
	path_out := path.Clean(path_in)
	if strings.HasSuffix(path_in, "/") && !strings.HasSuffix(path_out, "/") {
		path_out += "/"
	}
	if !strings.HasPrefix(path_out, "/") {
		path_out = "/" + path_out
	}
	url.Path = path_out
	// if RawPath is empty it is assumed to be equal to Path
	// (RequestURI() will just use Path and will not contain any escaped
	// elements).
	//
	// This approach makes it impossible to use wwwhisper for apps that
	// encode data in paths, paths are always authenticated and then
	// passed to the app as decoded, the information which parts were
	// encoded is lost. This is to ensure auth layer and app interpret
	// the path in the same way. For example a request to /admin/%2E%2E/
	// is normalized as the request to the root document /, and app never sees
	// the original /admin/%2E%2E/ path.
	url.RawPath = ""
}

func NewAuthHandler(wwwhisperURL *url.URL, log *slog.Logger, appHandler http.Handler) http.Handler {
	authURL := wwwhisperURL.String() + "/wwwhisper/auth/api/is-authorized/?path="
	// TODO: OK to reuse?
	client := &http.Client{}
	wwwhisperProxy := NewReverseProxy(wwwhisperURL, log, true)

	makeAuthRequest := func(r *http.Request) (*http.Response, error) {
		// .Path has escape characters decoded (/ instead of %2F)
		authReq, err := http.NewRequest("GET", authURL+r.URL.Path, nil)
		if err != nil {
			// This should never happen: method is hardcoded to GET, authURL
			// is for sure parsable because if comes from the already parsed
			// url.URL, other errors are not reported by NewRequest, but client.Do
			return nil, err
		}
		copyRequestHeaders(authReq, r)
		setSiteURLHeader(authReq, r)
		authReq.Header.Set("User-Agent", "go-"+Version)
		return client.Do(authReq)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		normalize(r.URL)
		// TODO: cleanup logs
		log.Info("wwwhisper request", "path", r.URL.Path)
		if strings.HasPrefix(r.URL.Path, "/wwwhisper/auth/") {
			// login/logout/send-token etc. always allowed, doesn't require authorization.
			wwwhisperProxy.ServeHTTP(w, r)
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
			wwwhisperProxy.ServeHTTP(w, r)
		} else {
			appHandler.ServeHTTP(w, r)
		}
	})
}

func Run(wwwhisperURL string, protectedAppPort string, proxyToPort string) error {
	wwwhisperURLParsed, err := url.Parse(wwwhisperURL)
	if err != nil {
		return fmt.Errorf("wwwhisper url has invalid format: %s; %w", wwwhisperURL, err)
	}

	proxyTarget, err := url.Parse("http://localhost:" + proxyToPort)
	if err != nil {
		return fmt.Errorf("App port has invalid format: %s; %w", proxyToPort, err)
	}

	mux := http.NewServeMux()
	// TODO: tune timeouts
	// TODO: set ErrorLogger
	s := http.Server{
		Addr:         ":" + protectedAppPort,
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 20 * time.Second,
		Handler:      mux,
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{})
	log := slog.New(handler)
	appProxy := NewReverseProxy(proxyTarget, log, false)
	mux.Handle("/", NewAuthHandler(wwwhisperURLParsed, log, appProxy))

	err = s.ListenAndServe()
	if err != http.ErrServerClosed {
		return err
	}
	return nil
}

func run() error {
	wwwhisperURL := os.Getenv("WWWHISPER_URL")
	if wwwhisperURL == "" {
		return errors.New("WWWHISPER_URL environment variable is not set")
	}
	protectedAppPort := os.Getenv("PORT")
	if protectedAppPort == "" {
		return errors.New("PORT environment variable is not set")
	}
	appPort := os.Getenv("PROXY_TO_PORT")
	if appPort == "" {
		return errors.New("PROXY_TO_PORT environment variable is not set")
	}
	return Run(wwwhisperURL, protectedAppPort, appPort)
}

func die(message string) {
	fmt.Fprintln(os.Stderr, "Error:", message)
	os.Exit(1)
}

func main() {
	err := run()
	if err != nil {
		die(err.Error())
	}
}
