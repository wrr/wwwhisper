package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wrr/wwwhispergo/internal/timer"
)

type Port uint16

type Config struct {
	PidFilePath  string
	NoOverlay    bool
	WwwhisperURL *url.URL
	Listen       Port
	ProxyTo      Port
	LogLevel     slog.Level
}

const Version string = "1.0.3"
const overlayToInject = `
<script src="/wwwhisper/auth/iframe.js"></script>
`

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

func newReverseProxy(target *url.URL, log *slog.Logger, proxyToWwwhisper bool, noOverlay bool) *httputil.ReverseProxy {
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
			// Stored for logging purposes.
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

func NewTimer(duration time.Duration) Timer {
	return timer.NewTimer(duration)
}

func newRootHandler(wwwhisperURL *url.URL, log *slog.Logger, appHandler http.Handler) http.Handler {
	remote_store := NewRemoteAuthStore(wwwhisperURL)
	caching_store := NewCachingAuthStore(remote_store, NewTimer, log)
	guard := NewAccessGuard(caching_store, log)

	// wwwhisper HTML responses already have the logout overlay added.
	noOverlay := true
	wwwhisperProxy := newReverseProxy(wwwhisperURL, log, true, noOverlay)

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		start := time.Now()

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
		granted := guard.Handle(rw, req)
		if !granted {
			authStatus = "denied"
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
	proxyTarget, _ := url.Parse(fmt.Sprintf("http://localhost:%d", cfg.ProxyTo))

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel})
	log := slog.New(handler)

	mux := http.NewServeMux()
	server := http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Listen),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       20 * time.Second,
		Handler:           mux,
		ErrorLog:          slog.NewLogLogger(handler, slog.LevelError),
	}
	server.SetKeepAlivesEnabled(true)

	appProxy := newReverseProxy(proxyTarget, log, false, cfg.NoOverlay)
	mux.Handle("/", newRootHandler(cfg.WwwhisperURL, log, appProxy))

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
