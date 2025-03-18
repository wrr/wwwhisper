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
	NoOverlay    bool
	WwwhisperURL *url.URL
	ExternalPort Port
	ProxyToPort  Port
	LogLevel     slog.Level
}

// Responses from wwwhisper contain headers added by Heroku router
// that are also added by the router in front of the app. For the Via
// header it can be considered OK (although confusing), for
// Nel/Report-To/Reporting-Endpoints headers the duplication should be
// removed. We remove all these headers.
//
// In addition we drop the User header which is present in 403
// responses produced by /wwwwhisper/auth/api/is-authorized endpoint.
// In general, returning the User header is not wrong, the information
// it contains can be obtained anyway from the
// /wwwhisper/auth/api/whoami endpoint, but to avoid it being treated
// as some kind of a public API, we mask the header.
var headersToDrop = map[string]bool{
	"Via":                 true,
	"Nel":                 true,
	"Report-To":           true,
	"Reporting-Endpoints": true,
	"User":                true,
}

// Store HTTP status in context for logging purposes. An alternative
// is to wrap ResponseWritter to capture the status,
// but the ResponseWritter implements several optional interfaces which
// makes such wrapping verbose, complex and prone to problems when new such
// interfaces are introduced in future version of net/http.
type statusCodeKey struct{}

func parsePort(in string) (Port, error) {
	inInt, err := strconv.Atoi(in)
	if err != nil {
		return 0, fmt.Errorf("failed to convert %s to port number: %v", in, err)
	}
	if inInt < 0 || inInt > 0xffff {
		return 0, fmt.Errorf("port number out of range %d", inInt)
	}
	return Port(inInt), nil
}

func copyAuthRequestHeaders(dst *http.Request, src *http.Request) {
	// Cookies identify the user, Accept is used by the wwwhisper
	// backend in case request is denied to know if the error returned
	// should be HTML.
	forwardedHeaders := []string{"Accept", "Accept-Language", "Cookie"}
	for _, header := range forwardedHeaders {
		dst.Header.Set(header, src.Header.Get(header))
	}
}

func copyResponse(w http.ResponseWriter, src *http.Response) error {
	for key, values := range src.Header {
		if headersToDrop[key] {
			continue
		}
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

func basicAuthCredentials(url *url.URL) string {
	username := url.User.Username()
	password, isPasswordSet := url.User.Password()
	if !isPasswordSet {
		return ""
	}
	toEncode := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(toEncode))
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

func NewReverseProxy(target *url.URL, log *slog.Logger, proxyToWwwhisper bool, noOverlay bool) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{}
	proxy.ErrorLog = slog.NewLogLogger(log.Handler(), slog.LevelError)
	credentials := basicAuthCredentials(target)

	proxy.Rewrite = func(req *httputil.ProxyRequest) {
		req.Out.URL.Scheme = target.Scheme
		req.Out.URL.Host = target.Host
		req.Out.Header["X-Forwarded-For"] = req.In.Header["X-Forwarded-For"]
		req.SetXForwarded()
		// In the chains of proxies (for example on Heroku where wwwhisper
		// is behind the Heroku router which terminates the HTTPS) pass
		// the original X-Forwarded-Proto to the app, so the app can
		// recognize if the client connection used HTTPS.
		proto := req.In.Header.Get("X-Forwarded-Proto")
		if len(proto) > 0 {
			req.Out.Header.Set("X-Forwarded-Proto", proto)
		}
		if proxyToWwwhisper {
			setSiteURLHeader(req.Out, req.In)
			// When proxying to wwwhisper the host header needs to contain
			// hostname parsed from the WWWHISPER_URL, not hostname of the
			// protected site. Otherwise wwwhisper backend hosting service
			// (Heroku at this moment) is not able to correctly route the
			// request (the Site-Url header contains the protected site
			// hostname).
			req.Out.Host = target.Host
		}
		if credentials != "" {
			req.Out.Header.Set("Authorization", credentials)
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		if statusCode, ok := resp.Request.Context().Value(statusCodeKey{}).(*int); ok {
			*statusCode = resp.StatusCode
		}
		if proxyToWwwhisper {
			for key := range headersToDrop {
				resp.Header.Del(key)
			}
		}
		if !noOverlay {
			return injectOverlay(resp)
		}
		return nil
	}
	return proxy
}

func normalize(url *url.URL) {
	pathIn := url.Path
	pahtOut := path.Clean(pathIn)
	if strings.HasSuffix(pathIn, "/") && !strings.HasSuffix(pahtOut, "/") {
		pahtOut += "/"
	}
	if !strings.HasPrefix(pahtOut, "/") {
		pahtOut = "/" + pahtOut
	}
	url.Path = pahtOut
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
	// Connection keepalive is on by default.
	authClient := &http.Client{
		Jar:     nil,
		Timeout: 7 * time.Second,
	}

	// wwwhisper HTML responses already have the logout overlay added.
	noOverlay := true
	wwwhisperProxy := NewReverseProxy(wwwhisperURL, log, true, noOverlay)

	makeAuthRequest := func(r *http.Request) (*http.Response, error) {
		// Path has escape characters decoded (/ instead of %2F)
		authReq, err := http.NewRequestWithContext(r.Context(), "GET", authURL+r.URL.Path, nil)
		if err != nil {
			// This should never happen: method is hardcoded to GET, authURL
			// is for sure parsable because if comes from the already parsed
			// url.URL, other errors are not reported by NewRequest, but client.Do
			return nil, err
		}
		copyAuthRequestHeaders(authReq, r)
		setSiteURLHeader(authReq, r)
		authReq.Host = wwwhisperURL.Host
		authReq.Header.Set("User-Agent", "go-"+Version)
		return authClient.Do(authReq)
	}

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		start := time.Now()
		normalize(req.URL)

		authStatus := ""
		statusCode := 0
		ctx := context.WithValue(req.Context(), statusCodeKey{}, &statusCode)
		req = req.WithContext(ctx)

		defer func() {
			duration := time.Since(start)
			log.Info("wwwhisper",
				slog.String("method", req.Method),
				slog.String("path", req.URL.Path),
				slog.String("auth", authStatus),
				slog.Int("status", statusCode),
				slog.Duration("timer", duration),
			)
		}()

		if strings.HasPrefix(req.URL.Path, "/wwwhisper/auth/") {
			// login/logout/send-token etc. always allowed, doesn't require authorization.
			authStatus = "open"
			wwwhisperProxy.ServeHTTP(rw, req)
			return
		}
		authResp, err := makeAuthRequest(req)
		if err != nil {
			authStatus = "failed"
			statusCode = http.StatusInternalServerError
			log.Warn("wwwhisper", "error", err.Error())
			// Do not return err.Error() to the user as it can contain sensitive
			// data.
			http.Error(rw, "Internal server error: auth request", statusCode)
			return
		}
		defer authResp.Body.Close()
		if authResp.StatusCode != http.StatusOK {
			authStatus = "denied"
			statusCode = authResp.StatusCode
			err = copyResponse(rw, authResp)
			if err != nil {
				log.Error("Error copying auth response: " + err.Error())
			}
			return
		}

		authStatus = "granted"
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
			return fmt.Errorf("error writing PID file: %v", err)
		}
		defer os.Remove(cfg.PidFilePath)
	}

	// error should never happen
	proxyTarget, _ := url.Parse(fmt.Sprintf("http://localhost:%d", cfg.ProxyToPort))

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel})
	log := slog.New(handler)

	mux := http.NewServeMux()
	server := http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.ExternalPort),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       20 * time.Second,
		Handler:           mux,
		ErrorLog:          slog.NewLogLogger(handler, slog.LevelError),
	}
	server.SetKeepAlivesEnabled(true)

	appProxy := NewReverseProxy(proxyTarget, log, false, cfg.NoOverlay)
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
	case <-sigChan:
		log.Info("signal received, terminating the server")
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
		return 0, fmt.Errorf("%s environment variable is invalid: %v", envVarName, err)
	}
	return port, nil
}

func newConfig(pidFilePath string) (Config, error) {
	_, noOverlay := os.LookupEnv("WWWHISPER_NO_OVERLAY")
	config := Config{
		PidFilePath: pidFilePath,
		NoOverlay:   noOverlay,
		LogLevel:    parseLogLevel(os.Getenv("WWWHISPER_LOG")),
	}
	wwwhisperURL := os.Getenv("WWWHISPER_URL")
	if wwwhisperURL == "" {
		return Config{}, errors.New("WWWHISPER_URL environment variable is not set")
	}

	var err error
	config.WwwhisperURL, err = url.Parse(wwwhisperURL)
	if err != nil {
		return Config{}, fmt.Errorf("WWWHISPER_URL has invalid format: %s; %v", wwwhisperURL, err)
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

func die(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
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
		die(err)
	}
	if flag.NArg() > 0 {
		die(fmt.Errorf("unrecognized arguments: %v", flag.Args()))
	}

	if *versionFlag {
		fmt.Println(Version)
		return
	}

	config, err := newConfig(*pidFileFlag)
	if err == nil {
		err = Run(config)
	}
	if err != nil {
		die(err)
	}

}
