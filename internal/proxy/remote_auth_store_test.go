package proxy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/wrr/wwwhispergo/internal/proxy/response"
	"github.com/wrr/wwwhispergo/internal/proxytest"
)

func TestRemoteAuthStore_Whoami(t *testing.T) {
	server := proxytest.NewAuthServer(t)
	defer server.Close()
	store := NewRemoteAuthStore(server.URL)

	tests := []struct {
		name       string
		cookie     string
		wantUser   *response.Whoami
		wantErrMsg string
	}{
		{
			name:   "authenticated admin user",
			cookie: "alice-cookie",
			wantUser: &response.Whoami{
				ModId:   server.ModId,
				ID:      "alice",
				Email:   "alice@example.com",
				IsAdmin: true,
			},
		},
		{
			name:   "authenticated non-admin user",
			cookie: "bob-cookie",
			wantUser: &response.Whoami{
				ModId:   server.ModId,
				ID:      "bob",
				Email:   "bob@example.org",
				IsAdmin: false,
			},
		},
		{
			name:   "unauthenticated user",
			cookie: "unknown-cookie",
			wantUser: &response.Whoami{
				ModId:   server.ModId,
				ID:      "",
				Email:   "",
				IsAdmin: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := store.Whoami(tt.cookie)

			if tt.wantErrMsg != "" {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.wantErrMsg)
				} else if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.wantErrMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if !reflect.DeepEqual(resp, tt.wantUser) {
				t.Errorf("Whoami() got = %+v, want %+v", resp, tt.wantUser)
			}
		})
	}
}

func TestRemoteAuthStore_Locations(t *testing.T) {
	server := proxytest.NewAuthServer(t)
	defer server.Close()
	store := NewRemoteAuthStore(server.URL)

	resp, err := store.Locations()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if resp.ModId != server.ModId {
		t.Errorf("ModId invalid %v", resp.ModId)
	}

	if len(resp.Entries) != len(server.Locations) {
		t.Errorf("Locations len invalid %v", len(resp.Entries))
		return
	}

	for i, loc := range resp.Entries {
		if loc.Path != server.Locations[i].Path {
			t.Errorf("location path invalid %v", loc.Path)
		}
		if loc.ID != server.Locations[i].ID {
			t.Errorf("Location ID invalid %v", loc.ID)
		}
		if loc.OpenAccess != server.Locations[i].OpenAccess {
			t.Errorf("Location OpenAccess invalid %v", loc.OpenAccess)
		}
	}
}

func TestRemoteAuthStore_LoginNeededPage(t *testing.T) {
	server := proxytest.NewAuthServer(t)
	defer server.Close()
	store := NewRemoteAuthStore(server.URL)

	html, err := store.LoginNeededPage()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if html != server.LoginNeeded {
		t.Errorf("LoginNeededPage() invalid %q", html)
	}
}

func TestRemoteAuthStore_ForbiddenPage(t *testing.T) {
	server := proxytest.NewAuthServer(t)
	defer server.Close()
	store := NewRemoteAuthStore(server.URL)

	html, err := store.ForbiddenPage()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if html != server.Forbidden {
		t.Errorf("ForbiddenPage() invalid %q", html)
	}
}

func TestRemoteAuthStore_ConnectionErrorHandling(t *testing.T) {
	server := proxytest.NewAuthServer(t)
	// Close the server to trigger network errors.
	server.Close()
	store := NewRemoteAuthStore(server.URL)

	t.Run("whoami with connection error", func(t *testing.T) {
		_, err := store.Whoami("any-cookie")
		if err == nil {
			t.Error("Error not returned")
		}
	})

	t.Run("locations with connection error", func(t *testing.T) {
		_, err := store.Locations()
		if err == nil {
			t.Error("Error not returned")
		}
	})

	t.Run("login needed page with connection error", func(t *testing.T) {
		_, err := store.LoginNeededPage()
		if err == nil {
			t.Error("Error not returned")
		}
	})

	t.Run("forbidden page with connection error", func(t *testing.T) {
		_, err := store.ForbiddenPage()
		if err == nil {
			t.Error("Error not returned")
		}
	})
}

func TestRemoteAuthStore_InvalidStatus(t *testing.T) {
	server := proxytest.NewAuthServer(t)
	store := NewRemoteAuthStore(server.URL)
	server.StatusCode = 500

	t.Run("whoami with connection error", func(t *testing.T) {
		_, err := store.Whoami("any-cookie")
		if err == nil || !strings.Contains(err.Error(), "failed: 500") {
			t.Errorf("Unexpected error %v", err)
		}
	})

	t.Run("locations with connection error", func(t *testing.T) {
		_, err := store.Locations()
		if err == nil || !strings.Contains(err.Error(), "failed: 500") {
			t.Errorf("Unexpected error %v", err)
		}
	})

	t.Run("login needed page with connection error", func(t *testing.T) {
		_, err := store.LoginNeededPage()
		if err == nil || !strings.Contains(err.Error(), "failed: 500") {
			t.Errorf("Unexpected error %v", err)
		}
	})

	t.Run("forbidden page with connection error", func(t *testing.T) {
		_, err := store.ForbiddenPage()
		if err == nil || !strings.Contains(err.Error(), "failed: 500") {
			t.Errorf("Unexpected error %v", err)
		}
	})
}

func TestRemoteAuthStore_InvalidJSON(t *testing.T) {
	server := proxytest.NewAuthServer(t)
	defer server.Close()
	store := NewRemoteAuthStore(server.URL)

	server.ReturnInvalidJson()

	t.Run("whoami with invalid JSON", func(t *testing.T) {
		_, err := store.Whoami("any-cookie")
		if err == nil || !strings.Contains(err.Error(), "error parsing whoami JSON") {
			t.Errorf("Unexpected error %v", err)
		}
	})
	t.Run("locations with invalid JSON", func(t *testing.T) {
		_, err := store.Locations()
		if err == nil || !strings.Contains(err.Error(), "error parsing locations JSON") {
			t.Errorf("Unexpected error %v", err)
		}
	})
}

func TestRemoteAuthStore_InvalidContentType(t *testing.T) {
	server := proxytest.NewAuthServer(t)
	defer server.Close()
	store := NewRemoteAuthStore(server.URL)

	server.ContentTypeHTML = "text/plain; charset=utf-8"

	t.Run("login needed page with invalid content type", func(t *testing.T) {
		_, err := store.LoginNeededPage()
		if err == nil || !strings.Contains(err.Error(), "invalid content type") {
			t.Errorf("Expected error about invalid content type, got: %v", err)
			t.Errorf("Unexpected error %v", err)
		}
	})

	t.Run("forbidden page with invalid content type", func(t *testing.T) {
		_, err := store.ForbiddenPage()
		if err == nil || !strings.Contains(err.Error(), "invalid content type") {
			t.Errorf("Unexpected error %v", err)
		}
	})
}
