package proxytest

import (
	"encoding/json"
	"net/http"

	"github.com/wrr/wwwhispergo/internal/proxy"
)

type Store struct {
	handler     http.Handler
	ModId       int
	Users       map[string]proxy.WhoamiResponse
	Locations   []proxy.Location
	LoginNeeded string
	Forbidden   string
}

func NewStore() *Store {
	mux := http.NewServeMux()
	users := make(map[string]proxy.WhoamiResponse)
	users["alice-cookie"] = proxy.WhoamiResponse{
		ID:      "alice",
		Email:   "alice@example.com",
		IsAdmin: true,
	}
	users["bob-cookie"] = proxy.WhoamiResponse{
		ID:      "bob",
		Email:   "bob@example.org",
		IsAdmin: false,
	}

	store := &Store{
		handler: mux,
		Users:   users,
		Locations: []proxy.Location{
			{
				Path:       "/",
				ID:         "loc-root",
				Self:       "/api/locations/loc-root",
				OpenAccess: false,
				AllowedUsers: []proxy.User{
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
				AllowedUsers: []proxy.User{
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
		resp := proxy.WhoamiResponse{
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
		resp := proxy.LocationsResponse{
			ModId:     store.ModId,
			Locations: store.Locations,
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

	return store
}
