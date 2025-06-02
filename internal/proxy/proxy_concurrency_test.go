package proxy

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestConcurrentRequests(t *testing.T) {
	testEnv := newTestEnv(t)
	defer testEnv.dispose()

	tests := []struct {
		name           string
		path           string
		cookie         string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "open location",
			path:           "/open",
			cookie:         "alice-cookie",
			expectedStatus: http.StatusOK,
			expectedBody:   "Hello world",
		},
		{
			name:           "admin allowed",
			path:           "/wwwhisper/admin/",
			cookie:         "alice-cookie",
			expectedStatus: http.StatusOK,
			expectedBody:   testEnv.AuthServer.Admin,
		},
		{
			name:           "admin forbidden",
			path:           "/wwwhisper/admin/",
			cookie:         "bob-cookie",
			expectedStatus: http.StatusForbidden,
			expectedBody:   testEnv.AuthServer.Forbidden,
		},
		{
			name:           "app not allowed",
			path:           "/protected",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   testEnv.AuthServer.LoginNeeded,
		},
		{
			name:           "app allowed",
			path:           "/protected",
			cookie:         "bob-cookie",
			expectedStatus: http.StatusOK,
			expectedBody:   "Hello world",
		},
		{
			name:           "open login page",
			path:           "/wwwhisper/auth/login",
			expectedStatus: http.StatusOK,
			expectedBody:   "login response",
		},
	}

	const (
		goroutines = 40
		testLoops  = 20
	)
	totalRequests := goroutines * len(tests) * testLoops

	var wg sync.WaitGroup
	results := make(chan error, totalRequests)

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{
				Timeout: 5 * time.Second,
			}

			for range testLoops {
				for _, cfg := range tests {
					req, _ := http.NewRequest("GET", testEnv.ExternalURL+cfg.path, nil)
					if cfg.cookie != "" {
						req.Header.Add("Cookie", "wwwhisper-sessionid="+cfg.cookie)
					}
					req.Header.Add("Accept", "text/html")
					resp, err := client.Do(req)
					results <- checkResponse(resp, err, cfg.expectedStatus, &cfg.expectedBody)
				}
			}
		}()
	}
	wg.Wait()
	close(results)

	done := 0
	for err := range results {
		done += 1
		if err != nil {
			t.Errorf("Request failed: %v", err)
		}
	}
	if done != totalRequests {
		t.Errorf("Unexpected number of requests %d vs %d", done, totalRequests)
	}
}
