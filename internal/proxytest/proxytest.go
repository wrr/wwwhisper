package proxytest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/wrr/wwwhispergo/internal/proxy/response"
)

type AuthServer struct {
	server      *httptest.Server
	URL         *url.URL
	ModId       int
	Users       map[string]response.Whoami
	Locations   []response.Location
	LoginNeeded string
	Forbidden   string
}

func (a *AuthServer) Close() {
	defer a.server.Close()
}

func NewAuthServer(t *testing.T) *AuthServer {
	t.Helper()
	users := make(map[string]response.Whoami)
	users["alice-cookie"] = response.Whoami{
		ID:      "alice",
		Email:   "alice@example.com",
		IsAdmin: true,
	}
	users["bob-cookie"] = response.Whoami{
		ID:      "bob",
		Email:   "bob@example.org",
		IsAdmin: false,
	}

	store := &AuthServer{
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
		LoginNeeded: "<html><body>Login needed</body></html>",
		Forbidden:   "<html><body>Forbidden</body></html>",
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
			ModId: store.ModId,
		}
		user, ok := store.Users[requestBody.Cookie]
		if ok {
			resp.ID = user.ID
			resp.Email = user.Email
			resp.IsAdmin = user.IsAdmin
		}
		w.Header().Set("Content-Type", "application/json")
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
		resp := response.Locations{
			ModId:   store.ModId,
			Entries: store.Locations,
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

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(store.LoginNeeded))
	})

	mux.HandleFunc("/api/forbidden/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(store.Forbidden))
	})

	store.server = httptest.NewServer(mux)
	url, err := url.Parse(store.server.URL)
	if err != nil {
		t.Fatalf("Failed to parse server URL: %v", err)
	}
	store.URL = url
	return store
}
