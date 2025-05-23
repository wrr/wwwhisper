package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type LogTestEnv struct {
	t      *testing.T
	logger *slog.Logger
	buf    *bytes.Buffer
}

func newLogTestEnv(t *testing.T) *LogTestEnv {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	return &LogTestEnv{
		t:      t,
		logger: slog.New(handler),
		buf:    &buf,
	}
}

func (tl *LogTestEnv) newRequestLogger(req *http.Request) (*http.Request, *RequestLogger) {
	return NewRequestLogger(req, tl.logger)
}

func (tl *LogTestEnv) output() map[string]interface{} {
	tl.t.Helper()
	var logEntry map[string]interface{}
	if err := json.Unmarshal(tl.buf.Bytes(), &logEntry); err != nil {
		tl.t.Fatalf("Failed to parse log output: %v", err)
	}
	return logEntry
}

func (tl *LogTestEnv) newRequest(method string, path string) *http.Request {
	tl.t.Helper()
	req, err := http.NewRequest(method, path, nil)
	if err != nil {
		tl.t.Fatalf("Failed to create request: %v", err)
	}
	return req
}

func (tl *LogTestEnv) checkOutput(method string, path string, status int, auth string) error {
	logEntry := tl.output()
	expected := map[string]interface{}{
		"msg":    "wwwhisper",
		"method": method,
		"path":   path,
	}
	if status != 0 {
		expected["status"] = float64(status) // JSON numbers are float64
	}
	if auth != "" {
		expected["auth"] = auth
	}
	for key, value := range expected {
		if got := logEntry[key]; got != value {
			return fmt.Errorf("Expected %s %v, got %v", key, value, got)
		}
		delete(logEntry, key)
	}

	timer, ok := logEntry["timer"].(string)
	if !ok {
		return fmt.Errorf("Timer is not a string, got %T", logEntry["timer"])
	}
	if !strings.HasSuffix(timer, "ms") {
		return fmt.Errorf("Timer does not end with 'ms', %v", timer)
	}
	delete(logEntry, "timer")

	// Standard log entries:

	_, ok = logEntry["time"]
	if !ok {
		return fmt.Errorf("Time entry missing")
	}
	delete(logEntry, "time")

	level, ok := logEntry["level"]
	if !ok || level != "INFO" {
		return fmt.Errorf("Invalid log level %v", level)
	}
	delete(logEntry, "level")

	for key := range logEntry {
		return fmt.Errorf("Unexpected log entry key: %s", key)
	}
	return nil
}

func TestNewRequestLogger(t *testing.T) {
	testEnv := newLogTestEnv(t)

	req := testEnv.newRequest("GET", "/test/path")
	newReq, logger := testEnv.newRequestLogger(req)

	if newReq == req {
		t.Error("Expected new request instance, got same instance")
	}
	if newReq.Context() == req.Context() {
		t.Error("Expected new context, got same context")
	}
	if logger == nil {
		t.Fatal("Expected RequestLogger instance, got nil")
	}
	if logger.log == nil {
		t.Error("Expected logger to be set")
	}
	if logger.start.IsZero() {
		t.Error("Expected start time to be set")
	}

	logger.Done()
	err := testEnv.checkOutput("GET", "/test/path", 0, "")
	if err != nil {
		t.Error(err)
	}

}

func TestGetRequestLogger(t *testing.T) {
	t.Run("with logger in context", func(t *testing.T) {
		testEnv := newLogTestEnv(t)
		req := testEnv.newRequest("GET", "/test")

		newReq, originalLogger := testEnv.newRequestLogger(req)
		retrievedLogger := GetRequestLogger(newReq)

		if retrievedLogger != originalLogger {
			t.Error("Expected to retrieve the same logger instance")
		}
	})

	t.Run("without logger in context", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/test", nil)
		retrievedLogger := GetRequestLogger(req)

		if retrievedLogger != nil {
			t.Error("Expected nil logger for request without logger in context")
		}
	})
}

func TestRequestLogger_Output(t *testing.T) {
	testEnv := newLogTestEnv(t)
	req := testEnv.newRequest("PUT", "/foo")
	_, logger := testEnv.newRequestLogger(req)

	logger.AuthDenied()
	logger.HttpStatus(401)
	logger.Done()

	err := testEnv.checkOutput("PUT", "/foo", 401, "denied")
	if err != nil {
		t.Error(err)
	}
}

func TestRequestLogger_Output2(t *testing.T) {
	testEnv := newLogTestEnv(t)
	req := testEnv.newRequest("PUT", "/users/123")
	_, logger := testEnv.newRequestLogger(req)

	logger.HttpStatus(201)
	logger.AuthGranted()
	logger.Done()

	err := testEnv.checkOutput("PUT", "/users/123", 201, "granted")
	if err != nil {
		t.Error(err)
	}
}

func TestRequestLogger_OverwriteFields(t *testing.T) {
	testEnv := newLogTestEnv(t)
	req := testEnv.newRequest("POST", "/foo")
	_, logger := testEnv.newRequestLogger(req)

	logger.HttpStatus(200)
	logger.HttpStatus(404)
	logger.AuthGranted()
	logger.AuthDenied()
	logger.Done()

	err := testEnv.checkOutput("POST", "/foo", 404, "denied")
	if err != nil {
		t.Error(err)
	}
}

func TestRequestLogger_URLWithQueryParams(t *testing.T) {
	testEnv := newLogTestEnv(t)
	reqURL, _ := url.Parse("/search?q=test&limit=10")
	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
	}
	req = req.WithContext(context.Background())

	_, logger := testEnv.newRequestLogger(req)
	logger.Done()

	// Should only log the path, not query parameters
	err := testEnv.checkOutput("GET", "/search", 0, "")
	if err != nil {
		t.Error(err)
	}

}
