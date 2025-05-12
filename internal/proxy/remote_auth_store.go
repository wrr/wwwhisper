package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wrr/wwwhispergo/internal/proxy/response"
)

type remoteAuthStore struct {
	wwwhisperURL *url.URL
	httpClient   *http.Client
}

const requestTimeout = 7 * time.Second

func NewRemoteAuthStore(wwwhisperURL *url.URL) *remoteAuthStore {
	return &remoteAuthStore{
		wwwhisperURL: wwwhisperURL,
		// Connection keepalive is on by default.
		httpClient: &http.Client{
			Jar:     nil,
			Timeout: requestTimeout,
		},
	}
}

// TODO: proxied whoami should work differently, csrf cookies should
// be included only if they are present in the original request.
func (r remoteAuthStore) Whoami(cookie string) (*response.Whoami, error) {
	url := r.wwwhisperURL.String() + "/api/whoami/"
	args := map[string]string{
		"cookie": cookie,
	}
	jsonArgs, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	// TODO: use new request with context everywhere?
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonArgs))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := r.httpClient.Do(req)
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

func (r remoteAuthStore) Locations() (*response.Locations, error) {
	url := r.wwwhisperURL.String() + "/api/locations/"
	resp, err := r.httpClient.Get(url)
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

func (r remoteAuthStore) getPage(path string) (string, error) {
	url := r.wwwhisperURL.String() + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Accept", "text/html")
	resp, err := r.httpClient.Do(req)
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

func (r remoteAuthStore) LoginNeededPage() (string, error) {
	return r.getPage("/api/login-needed/")
}

func (r remoteAuthStore) ForbiddenPage() (string, error) {
	return r.getPage("/api/forbidden/")
}
