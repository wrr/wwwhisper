package proxy

import (
	"testing"
)

func TestLocationCanAccess(t *testing.T) {
	tests := []struct {
		name     string
		location Location
		userId   string
		expected bool
	}{
		{
			name: "open access",
			location: Location{
				Path:       "/public",
				OpenAccess: true,
			},
			userId:   "alice",
			expected: true,
		},
		{
			name: "user in allowed users",
			location: Location{
				Path:       "/private",
				OpenAccess: false,
				AllowedUsers: []User{
					{ID: "alice", Email: "alice@example.com"},
					{ID: "bob", Email: "bob@example.com"},
				},
			},
			userId:   "alice",
			expected: true,
		},
		{
			name: "user not in allowed users",
			location: Location{
				Path:       "/private",
				OpenAccess: false,
				AllowedUsers: []User{
					{ID: "alice", Email: "alice@example.com"},
					{ID: "bob", Email: "bob@example.com"},
				},
			},
			userId:   "jane",
			expected: false,
		},
		{
			name: "no users allowed",
			location: Location{
				Path:         "/restricted",
				OpenAccess:   false,
				AllowedUsers: []User{},
			},
			userId:   "alice",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.location.CanAccess(tt.userId); got != tt.expected {
				t.Errorf("Location.CanAccess() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestMatchingLocation(t *testing.T) {
	locations := []Location{
		{
			Path:       "/",
			OpenAccess: true,
			ID:         "root",
		},
		{
			Path:       "/docs/private",
			OpenAccess: false,
			ID:         "docs-private",
		},
		{
			Path:       "/docs/",
			OpenAccess: true,
			ID:         "docs",
		},
		{
			Path:       "/docs/privat",
			OpenAccess: false,
			ID:         "docs-privat",
		},
		{
			Path:       "/admin",
			OpenAccess: false,
			ID:         "admin",
		},
	}

	tests := []struct {
		path       string
		expectedID string
	}{
		{
			path:       "/",
			expectedID: "root",
		},
		{
			path:       "/foo",
			expectedID: "root",
		},
		{
			path:       "/foo/docs/",
			expectedID: "root",
		},
		{
			path:       "/admi",
			expectedID: "root",
		},
		{
			path:       "/admin",
			expectedID: "admin",
		},
		{
			path:       "/admin/foo",
			expectedID: "admin",
		},
		{
			path:       "/adminfoo",
			expectedID: "root",
		},
		{
			path:       "/docs",
			expectedID: "root",
		},
		{
			path:       "/docs/",
			expectedID: "docs",
		},
		{
			path:       "/docs/file.txt",
			expectedID: "docs",
		},
		{
			path:       "/docs/private",
			expectedID: "docs-private",
		},
		{
			path:       "/docs/private/secret.txt",
			expectedID: "docs-private",
		},
		{
			path:       "/docs/privat",
			expectedID: "docs-privat",
		},
		{
			path:       "/docs/privatx",
			expectedID: "docs",
		},
	}

	for _, tt := range tests {
		t.Run("["+tt.path+"]", func(t *testing.T) {
			got := MatchingLocation(locations, tt.path)
			if got.ID != tt.expectedID {
				t.Errorf("MatchingLocation(\"%v\") = %v, expected %v", tt.path, got.ID, tt.expectedID)
			}
		})
	}
}

func TestMatchingLocationNoRootEntry(t *testing.T) {
	locations := []Location{
		{
			Path:       "/foo/",
			OpenAccess: true,
			ID:         "foo",
		},
		{
			Path:       "/foo/bar/",
			OpenAccess: true,
			ID:         "bar",
		},
	}

	tests := []struct {
		path       string
		expectedID string
	}{
		{
			path:       "/",
			expectedID: "",
		},
		{
			path:       "/foo",
			expectedID: "",
		},
		{
			path:       "/a/foo/",
			expectedID: "",
		},
		{
			path:       "/foo/",
			expectedID: "foo",
		},
		{
			path:       "/foo/bar",
			expectedID: "foo",
		},
		{
			path:       "/foo/bar/",
			expectedID: "bar",
		},
	}

	for _, tt := range tests {
		t.Run("["+tt.path+"]", func(t *testing.T) {
			got := MatchingLocation(locations, tt.path)
			if got == nil {
				if (tt.expectedID != "") {
					t.Errorf("MatchingLocation() = nil expected %v", tt.expectedID)
				}
				return
			}
			if got.ID != tt.expectedID {
				t.Errorf("MatchingLocation(\"%v\") = %v, expected %v", tt.path, got.ID, tt.expectedID)
			}
		})
	}
}
