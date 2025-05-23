package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/wrr/wwwhispergo/internal/timer"
)

// A key under which *RequestLogger is stored in context.
type loggerKey struct{}

// RequestLogger allows to set a single HTTP request related
// attributes in several places in code. The attributes are then
// output as a single log line when Done() method is called.
type RequestLogger struct {
	log   *slog.Logger
	start time.Time
	attrs []slog.Attr
}

// HttpStatus stores status code of the request.
func (r *RequestLogger) HttpStatus(code int) {
	r.attrs = append(r.attrs, slog.Int("status", code))
}

// AuthGranted and AuthDenied store authorization status of the
// request.
func (r *RequestLogger) AuthGranted() {
	r.attrs = append(r.attrs, slog.String("auth", "granted"))
}

func (r *RequestLogger) AuthDenied() {
	r.attrs = append(r.attrs, slog.String("auth", "denied"))
}

// Must be called at the end of the request processing. Outputs all
// the request attributes as a single log entry.
func (r *RequestLogger) Done() {
	duration := time.Since(r.start)
	r.attrs = append(r.attrs, slog.String("timer", timer.MsString(duration)))
	r.log.LogAttrs(context.Background(), slog.LevelInfo, "wwwhisper", r.attrs...)
}

// NewRequestLogger creates a new request logger and stores it in a
// context. Returns a request with new context which the caller must
// use in place of the request passed to this function as the
// argument.
//
// Starts a request processing timer which is then output together
// with all other request attributes when the Done() method is called.
func NewRequestLogger(req *http.Request, log *slog.Logger) (*http.Request, *RequestLogger) {
	attrs := []slog.Attr{
		slog.String("method", req.Method),
		slog.String("path", req.URL.Path),
	}
	logger := &RequestLogger{
		log:   log,
		start: time.Now(),
		attrs: attrs,
	}
	ctx := context.WithValue(req.Context(), loggerKey{}, logger)
	return req.WithContext(ctx), logger
}

// GetRequestLogger retrieves a RequestLogger from a request
// context. Returns nil if called on request that do not have logger
// in the context (was not returned by NewRequestLogger function).
func GetRequestLogger(req *http.Request) *RequestLogger {
	logger, _ := req.Context().Value(loggerKey{}).(*RequestLogger)
	return logger
}
