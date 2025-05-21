package proxytest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/wrr/wwwhispergo/internal/proxy/response"
)

const basicAuthUser = "admin"
const basicAuthPassword = "sometestpassword"

type AuthServer struct {
	server          *httptest.Server
	Mux             *http.ServeMux
	URL             *url.URL
	ModId           int
	Users           map[string]*response.Whoami
	Locations       []response.Location
	LoginNeeded     string
	Forbidden       string
	Admin           string
	StatusCode      int
	ContentTypeHTML string
	ContentTypeJson string
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

func checkBasicAuthCredentials(req *http.Request) error {
	username, password, ok := req.BasicAuth()
	if !ok {
		return errors.New("credentials missing")
	}
	if username != basicAuthUser || password != basicAuthPassword {
		return errors.New("credentials do not match")
	}
	return nil

}

func requireBasicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := checkBasicAuthCredentials(r); err != nil {
			http.Error(w, "basic auth required: "+err.Error(), http.StatusUnauthorized)
		} else {
			next.ServeHTTP(w, r)
		}
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
				Path:       "/wwwhisper/admin/",
				Self:       "/api/locations/loc-admin",
				ID:         "loc-admin",
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
		Admin:           "<html><body>admin page</body></html>",
		StatusCode:      http.StatusOK,
		ContentTypeHTML: "text/html; charset=utf-8",
		ContentTypeJson: "application/json; charset=utf-8",
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/wwwhisper/auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", server.ContentTypeHTML)
		w.WriteHeader(server.StatusCode)
		w.Write([]byte("login response"))
	})

	mux.HandleFunc("/wwwhisper/admin/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", server.ContentTypeHTML)
		w.WriteHeader(server.StatusCode)
		w.Write([]byte(server.Admin))
	})

	mux.HandleFunc("/wwwhisper/admin/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		siteURL := r.Header.Get("Site-Url")
		w.Header().Set("Content-Type", server.ContentTypeJson)
		w.WriteHeader(server.StatusCode)
		var buf []byte
		buf = fmt.Appendf(buf, "{siteUrl: %q}", siteURL)
		w.Write(buf)
	})

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

	server.server = httptest.NewServer(requireBasicAuth(mux))
	server.Mux = mux
	urlParsed, err := url.Parse(server.server.URL)
	if err != nil {
		t.Fatalf("Failed to parse server URL: %v", err)
	}
	urlParsed.User = url.UserPassword(basicAuthUser, basicAuthPassword)
	server.URL = urlParsed
	return server
}

func NewLogger() *slog.Logger {
	options := &slog.HandlerOptions{}
	handler := slog.NewTextHandler(io.Discard /*os.Stderr*/, options)
	return slog.New(handler)
}
