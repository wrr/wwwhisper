package proxytest

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/wrr/wwwhispergo/internal/proxy/response"
)

type AuthServer struct {
	server          *httptest.Server
	URL             *url.URL
	ModId           int
	Users           map[string]*response.Whoami
	Locations       []response.Location
	LoginNeeded     string
	Forbidden       string
	StatusCode      int
	ContentTypeHTML string
}

func (a *AuthServer) Close() {
	defer a.server.Close()
}

func (a *AuthServer) ReturnInvalidJson() {
	a.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"invalid JSON`))
	})
}

func NewAuthServer(t *testing.T) *AuthServer {
	t.Helper()
	users := make(map[string]*response.Whoami)
	users["alice-cookie"] = &response.Whoami{
		ID:      "alice",
		Email:   "alice@example.com",
		IsAdmin: true,
	}
	users["bob-cookie"] = &response.Whoami{
		ID:      "bob",
		Email:   "bob@example.org",
		IsAdmin: false,
	}

	server := &AuthServer{
		ModId: 23,
		Users: users,
		Locations: []response.Location{
			{
				Path:       "/",
				ID:         "loc-root",
				Self:       "/api/locations/loc-root",
				OpenAccess: false,
				AllowedUsers: []response.User{
					{
						ID:    "alice",
						Email: "alice@example.com",
						Self:  "/api/users/alice",
					},
					{
						ID:    "bob",
						Email: "bob@example.org",
						Self:  "/api/users/bob",
					},
				},
			},
			{
				Path:       "/open",
				ID:         "loc-open",
				Self:       "/api/locations/loc-open",
				OpenAccess: true,
			},
			{
				Path:       "/protected/",
				Self:       "/api/locations/loc-protected",
				ID:         "loc-protected",
				OpenAccess: false,
				AllowedUsers: []response.User{
					{
						ID:    "alice",
						Email: "alice@example.com",
						Self:  "/api/users/alice",
					},
				},
			},
		},
		LoginNeeded:     "<html><body>Login needed</body></html>",
		Forbidden:       "<html><body>Forbidden</body></html>",
		StatusCode:      http.StatusOK,
		ContentTypeHTML: "text/html; charset=utf-8",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/whoami/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var requestBody struct {
			Cookie string `json:"cookie"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		resp := response.Whoami{
			ModId: server.ModId,
		}
		user, ok := server.Users[requestBody.Cookie]
		if ok {
			resp.ID = user.ID
			resp.Email = user.Email
			resp.IsAdmin = user.IsAdmin
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(server.StatusCode)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/api/locations/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(server.StatusCode)
		resp := response.Locations{
			ModId:   server.ModId,
			Entries: server.Locations,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/api/login-needed/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", server.ContentTypeHTML)
		w.WriteHeader(server.StatusCode)
		w.Write([]byte(server.LoginNeeded))
	})

	mux.HandleFunc("/api/forbidden/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", server.ContentTypeHTML)
		w.WriteHeader(server.StatusCode)
		w.Write([]byte(server.Forbidden))
	})

	server.server = httptest.NewServer(mux)
	url, err := url.Parse(server.server.URL)
	if err != nil {
		t.Fatalf("Failed to parse server URL: %v", err)
	}
	server.URL = url
	return server
}

func NewLogger() *slog.Logger {
	options := &slog.HandlerOptions{}
	handler := slog.NewTextHandler(io.Discard /*os.Stderr*/, options)
	return slog.New(handler)
}
