package proxy

import (
	"net/url"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	testCases := []struct {
		path_in    string
		path_out string
	}{
		{"/", "/"},
		{"/foo/bar", "/foo/bar"},
		{"/foo/bar/", "/foo/bar/"},
		{"/auth/api/login/../../../foo/", "/foo/"},
		{"//", "/"},
		{"", "/"},
		{"/../", "/"},
		{"/./././", "/"},
		{"/./././", "/"},
		{"/a/b/../../c", "/c"},
		{"/a/b/../../c/", "/c/"},
		{"/../../../../", "/"},
		{"/foo/./bar/../../bar", "/bar"},
		{"/foo/./bar/%2E%2E/%2E%2E/bar", "/bar"},
		{"/./././/", "/"},
		{"/x/y%2Fz", "/x/y/z"},
		{"", "/"},
		{"///", "/"},
	}

	for _, tc := range testCases {
		t.Run("["+tc.path_in+"]", func(t *testing.T) {
			u, err := url.Parse("http://example.com" + tc.path_in)
			if err != nil {
				t.Fatalf("Failed to parse URL: %v", err)
			}

			normalizePath(u)

			if u.Path != tc.path_out {
				t.Errorf("normalizePath(\"%s\"); expected %q, got %q", tc.path_in, tc.path_out, u.Path)
			}
			if u.RawPath != "" {
				t.Errorf("Expected empty RawPath, got %q", u.RawPath)
			}
		})
	}
}
