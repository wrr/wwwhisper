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
	"strconv"
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
	AllowHttp    bool
	LogLevel     slog.Level
}

const Version string = "1.0.6"
const Client string = "go-" + Version
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
//
// We also drop Mod-Id which is needed by the auth proxy for cache
// invalidation, but is not needed by the end client.
var headersToDrop = map[string]bool{
	"Via":                 true,
	"Nel":                 true,
	"Report-To":           true,
	"Reporting-Endpoints": true,
	"User":                true,
	"X-Mod-Id":            true,
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
	contentLength := resp.ContentLength
	if !strings.Contains(strings.ToLower(contentType), "text/html") ||
		contentLength == -1 || contentLength > 10*1024*1024 ||
		resp.Header.Get("Transfer-Encoding") != "" ||
		resp.Header.Get("Content-Encoding") != "" ||
		resp.Header.Get("Content-Range") != "" ||
		resp.Header.Get("Content-MD5") != "" {
		// Inject overlay only to HTML responses. Do not attempt to inject
		// iframe if the result content length is unknown, larger than
		// 10MB, or the result is chunked, compressed or checksummed.
		return nil
	}

	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

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

func scheme(r *http.Request) string {
	result := r.Header.Get("X-Forwarded-Proto")
	if result != "https" && result != "http" {
		if r.TLS != nil {
			result = "https"
		} else {
			result = "http"
		}
	}
	return result
}

func setSiteURLHeader(dst *http.Request, incoming *http.Request) {
	dst.Header.Set("Site-Url", scheme(incoming)+"://"+incoming.Host)
}

func getModId(resp *http.Response) (int, bool) {
	modIdStr := resp.Header.Get("X-Mod-Id")
	if modIdStr != "" {
		modId, err := strconv.Atoi(modIdStr)
		return modId, err == nil
	}
	return 0, false
}

type reverseProxyConfig struct {
	target           *url.URL
	log              *slog.Logger
	proxyToWwwhisper bool
	cachingStore     *cachingAuthStore
	noOverlay        bool
}

func newReverseProxy(cfg *reverseProxyConfig) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{}
	proxy.ErrorLog = slog.NewLogLogger(cfg.log.Handler(), slog.LevelError)
	credentials := basicAuthCredentials(cfg.target)

	proxy.Rewrite = func(req *httputil.ProxyRequest) {
		req.Out.URL.Scheme = cfg.target.Scheme
		req.Out.URL.Host = cfg.target.Host
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
		if cfg.proxyToWwwhisper {
			req.Out.Header.Set("X-Client", Client)
			setSiteURLHeader(req.Out, req.In)
			// When proxying to wwwhisper the host header needs to contain
			// hostname parsed from the WWWHISPER_URL, not hostname of the
			// protected site. Otherwise wwwhisper backend hosting service
			// (Heroku at this moment) is not able to correctly route the
			// request (the Site-Url header contains the protected site
			// hostname).
			req.Out.Host = cfg.target.Host
		}
		if credentials != "" {
			req.Out.Header.Set("Authorization", credentials)
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		req := resp.Request
		logger := GetRequestLogger(req.Context())
		if logger != nil {
			logger.HttpStatus(resp.StatusCode)
		}
		if cfg.proxyToWwwhisper {
			modId, ok := getModId(resp)
			if ok {
				cfg.cachingStore.CheckFreshness(modId)
			}
			for key := range headersToDrop {
				resp.Header.Del(key)
			}
		}
		if !cfg.noOverlay && req.Header.Get("User") != "" {
			// Inject overlay only if the user is authenticated.
			return injectOverlay(resp)
		}
		return nil
	}
	return proxy
}

func NewTimer(duration time.Duration) Timer {
	return timer.NewTimer(duration)
}

func newRootHandler(wwwhisperURL *url.URL, allowHttp bool, log *slog.Logger, appHandler http.Handler) http.Handler {
	remoteStore := NewRemoteAuthStore(wwwhisperURL, log)
	cachingStore := NewCachingAuthStore(remoteStore, NewTimer, log)
	guard := NewAccessGuard(cachingStore, log)

	cfg := &reverseProxyConfig{
		target:           wwwhisperURL,
		log:              log,
		proxyToWwwhisper: true,
		cachingStore:     cachingStore,
		noOverlay:        true, // wwwhisper HTML responses already have the logout overlay added.
	}
	wwwhisperProxy := newReverseProxy(cfg)

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		req, logger := NewRequestLogger(req, log)
		defer logger.Done()

		if !allowHttp && scheme(req) != "https" {
			httpsURL := "https://" + req.Host + req.RequestURI
			logger.HttpStatus(http.StatusMovedPermanently)
			http.Redirect(rw, req, httpsURL, http.StatusMovedPermanently)
			return
		}

		granted := guard.Handle(rw, req)
		if !granted {
			logger.AuthDenied()
			return
		}
		logger.AuthGranted()
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

	appProxy := newReverseProxy(&reverseProxyConfig{
		target:           proxyTarget,
		log:              log,
		proxyToWwwhisper: false,
		cachingStore:     nil,
		noOverlay:        cfg.NoOverlay,
	})
	mux.Handle("/", newRootHandler(cfg.WwwhisperURL, cfg.AllowHttp, log, appProxy))

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
