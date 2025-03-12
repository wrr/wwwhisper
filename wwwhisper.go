package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const Version string = "1.0.1"
const overlayToInject = `
<script src="/wwwhisper/auth/iframe.js"></script>
`

type Port uint16

type Config struct {
	PidFilePath  string
	WwwhisperURL *url.URL
	ExternalPort Port
	ProxyToPort  Port
	LogLevel     slog.Level
}

func parsePort(in string) (Port, error) {
	inInt, err := strconv.Atoi(in)
	if err != nil {
		return 0, fmt.Errorf("failed to convert %s to port number: %w", in, err)
	}
	if inInt < 0 || inInt > 0xffff {
		return 0, fmt.Errorf("port number out of range %d", inInt)
	}
	return Port(inInt), nil
}

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
	proxy.ErrorLog = slog.NewLogLogger(log.Handler(), slog.LevelError)
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

// ResponseWriter which captures http status for logging purposes.
type statusCapturingWriter struct {
	http.ResponseWriter
	status int
}

func (rw *statusCapturingWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func wrapResponseWriter(rw http.ResponseWriter) *statusCapturingWriter {
	return &statusCapturingWriter{
		ResponseWriter: rw,
		status:         http.StatusOK,
	}
}

func NewAuthHandler(wwwhisperURL *url.URL, log *slog.Logger, appHandler http.Handler) http.Handler {
	authURL := wwwhisperURL.String() + "/wwwhisper/auth/api/is-authorized/?path="
	authClient := &http.Client{
		Jar:     nil,
		Timeout: 20 * time.Second,
	}

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
		return authClient.Do(authReq)
	}

	return http.HandlerFunc(func(origWriter http.ResponseWriter, req *http.Request) {
		start := time.Now()
		var rw *statusCapturingWriter = wrapResponseWriter(origWriter)
		normalize(req.URL)

		auth_status := ""
		defer func() {
			duration := time.Since(start)
			log.Info("wwwhisper",
				slog.String("method", req.Method),
				slog.String("path", req.URL.Path),
				slog.String("auth", auth_status),
				slog.Int("status", rw.status),
				slog.Duration("timer", duration),
			)
		}()

		if strings.HasPrefix(req.URL.Path, "/wwwhisper/auth/") {
			// login/logout/send-token etc. always allowed, doesn't require authorization.
			auth_status = "open"
			wwwhisperProxy.ServeHTTP(rw, req)
			return
		}
		authResp, err := makeAuthRequest(req)
		if err != nil {
			auth_status = "failed"
			log.Warn("wwwhisper", "error", err.Error())
			// Do not return err.Error() to the user as it can contain sensitive
			// data.
			http.Error(rw, "Internal server error: auth request", http.StatusInternalServerError)
			return
		}
		defer authResp.Body.Close()
		if authResp.StatusCode != http.StatusOK {
			auth_status = "denied"
			err = copyResponse(rw, authResp)
			if err != nil {
				log.Error("Error copying auth response: " + err.Error())
			}
			return
		}

		auth_status = "granted"
		if strings.HasPrefix(req.URL.Path, "/wwwhisper/") {
			wwwhisperProxy.ServeHTTP(rw, req)
		} else {
			appHandler.ServeHTTP(rw, req)
		}
	})
}

func Run(cfg Config) error {
	if cfg.PidFilePath != "" {
		pidStr := fmt.Sprintf("%d\n", os.Getpid())
		if err := os.WriteFile(cfg.PidFilePath, []byte(pidStr), 0400); err != nil {
			return fmt.Errorf("Error writing PID to file %s: %w\n", cfg.PidFilePath, err)
		}
		defer os.Remove(cfg.PidFilePath)
	}

	// error should never happen
	proxyTarget, _ := url.Parse(fmt.Sprintf("http://localhost:%d", cfg.ProxyToPort))

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel})
	log := slog.New(handler)

	mux := http.NewServeMux()
	// TODO: tune timeouts
	server := http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ExternalPort),
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 20 * time.Second,
		Handler:      mux,
		ErrorLog:     slog.NewLogLogger(handler, slog.LevelError),
	}
	appProxy := NewReverseProxy(proxyTarget, log, false)
	mux.Handle("/", NewAuthHandler(cfg.WwwhisperURL, log, appProxy))

	serverStatus := make(chan error, 1)

	// Gracefully cancel on signal.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		err := server.ListenAndServe()
		if err != http.ErrServerClosed {
			serverStatus <- err
		}
		serverStatus <- nil
	}()

	select {
	case err := <-serverStatus:
		return err
	case _ = <-sigChan:
		log.Info("Signal received, terminating the server")
		break
	}
	// Singal received, shutdown the server.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return err
	}
	// Wait for the server exit status.
	return <-serverStatus
}

func parseLogLevel(logLevelStr string) slog.Level {
	switch strings.ToLower(logLevelStr) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "":
		// default if WWWHISPER_LOG is not set
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "off":
		return slog.LevelError + 1
	default:
		// Use Info if logLevelStr is set to any other string
		return slog.LevelInfo
	}
}

func portFromEnv(envVarName string) (Port, error) {
	portStr := os.Getenv(envVarName)
	if portStr == "" {
		return 0, fmt.Errorf("%s environment variable is not set", envVarName)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return 0, fmt.Errorf("%s environment variable is invalid: %w", envVarName, err)
	}
	return port, nil
}

func createConfig(pidFilePath string) (Config, error) {
	config := Config{
		PidFilePath: pidFilePath,
		LogLevel:    parseLogLevel(os.Getenv("WWWHISPER_LOG")),
	}
	wwwhisperURL := os.Getenv("WWWHISPER_URL")
	if wwwhisperURL == "" {
		return Config{}, errors.New("WWWHISPER_URL environment variable is not set")
	}

	var err error
	config.WwwhisperURL, err = url.Parse(wwwhisperURL)
	if err != nil {
		return Config{}, fmt.Errorf("WWWHISPER_URL has invalid format: %s; %w", wwwhisperURL, err)
	}

	config.ExternalPort, err = portFromEnv("PORT")
	if err != nil {
		return Config{}, err
	}
	config.ProxyToPort, err = portFromEnv("PROXY_TO_PORT")
	if err != nil {
		return Config{}, err
	}
	return config, nil
}

func die(message string) {
	fmt.Fprintln(os.Stderr, "Error:", message)
	os.Exit(1)
}

func main() {
	pidFileFlag := flag.String("pidfile", "", "Path to file where process ID is written.\n"+
		"The file is removed when the program terminates.")
	versionFlag := flag.Bool("version", false, "Print the program version")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "wwwhisper authorization reverse proxy\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	err := flag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		flag.Usage()
		os.Exit(1)
	}
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "Error: unrecognized arguments: %v\n\n", flag.Args())
		flag.Usage()
		os.Exit(1)
	}

	if *versionFlag {
		fmt.Println(Version)
		return
	}

	config, err := createConfig(*pidFileFlag)
	if err == nil {
		err = Run(config)
	}
	if err != nil {
		die(err.Error())
	}

}
