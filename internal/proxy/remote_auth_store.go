package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wrr/wwwhispergo/internal/proxy/response"
	"github.com/wrr/wwwhispergo/internal/timer"
)

type remoteAuthStore struct {
	wwwhisperURL *url.URL
	httpClient   *http.Client
	log          *slog.Logger
}

const requestTimeout = 7 * time.Second

func NewRemoteAuthStore(wwwhisperURL *url.URL, log *slog.Logger) *remoteAuthStore {
	return &remoteAuthStore{
		wwwhisperURL: wwwhisperURL,
		// Connection keepalive is on by default.
		httpClient: &http.Client{
			Jar:     nil,
			Timeout: requestTimeout,
		},
		log: log,
	}
}

func (r remoteAuthStore) debugLog(path string, resp *http.Response, err error, start time.Time) {
	if !r.log.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	attrs := []slog.Attr{
		slog.String("path", path),
		slog.String("timer", timer.MsString(time.Since(start))),
	}
	if err != nil {
		attrs = append(attrs, slog.Any("error", err))
	}
	if resp != nil {
		attrs = append(attrs, slog.Int("status", resp.StatusCode))
	}
	r.log.LogAttrs(context.Background(), slog.LevelDebug, "wwwhisper-out-request", attrs...)
}

// TODO: proxied whoami should work differently, csrf cookies should
// be included only if they are present in the original request.
func (r remoteAuthStore) Whoami(ctx context.Context, cookie string) (*response.Whoami, error) {
	start := time.Now()
	path := "/api/whoami/"
	url := r.wwwhisperURL.String() + path
	var err error
	var resp *http.Response
	defer func() {
		r.debugLog(path, resp, err, start)
	}()

	args := map[string]string{
		"cookie": cookie,
		"client": "go-" + Version,
	}
	jsonArgs, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonArgs))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err = r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("whoami failed: %d %s", resp.StatusCode, string(body))
	}
	var whoami response.Whoami
	err = json.Unmarshal(body, &whoami)
	if err != nil {
		return nil, fmt.Errorf("error parsing whoami JSON: %v", err)
	}
	return &whoami, nil
}

func (r remoteAuthStore) Locations(ctx context.Context) (*response.Locations, error) {
	start := time.Now()
	path := "/api/locations"
	url := r.wwwhisperURL.String() + path

	var err error
	var resp *http.Response
	defer func() {
		r.debugLog(path, resp, err, start)
	}()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err = r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("get locations failed: %d %s", resp.StatusCode, string(body))
	}
	var locations response.Locations
	err = json.Unmarshal(body, &locations)
	if err != nil {
		return nil, fmt.Errorf("error parsing locations JSON: %v", err)
	}
	return &locations, nil
}

func (r remoteAuthStore) getPage(ctx context.Context, path string) (string, error) {
	start := time.Now()
	url := r.wwwhisperURL.String() + path
	var err error
	var resp *http.Response
	defer func() {
		r.debugLog(path, resp, err, start)
	}()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Accept", "text/html")
	resp, err = r.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	result := string(body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("get %s failed: %d %s", path, resp.StatusCode, result)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "text/html") {
		return "", fmt.Errorf("get %s invalid content type: %s", path, contentType)
	}
	return result, nil
}

func (r remoteAuthStore) LoginNeededPage(ctx context.Context) (string, error) {
	return r.getPage(ctx, "/api/login-needed/")
}

func (r remoteAuthStore) ForbiddenPage(ctx context.Context) (string, error) {
	return r.getPage(ctx, "/api/forbidden/")
}
