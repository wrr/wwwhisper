// Copyright (C) 2025 Jan Wrobel <jan@wwwhisper.io>
// This program is freely distributable under the terms of the
// Simplified BSD License. See COPYING.

package proxy

import (
	"net/url"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	testCases := []struct {
		pathIn  string
		pathOut string
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
		t.Run("["+tc.pathIn+"]", func(t *testing.T) {
			u, err := url.Parse("http://example.com" + tc.pathIn)
			if err != nil {
				t.Fatalf("Failed to parse URL: %v", err)
			}

			normalizePath(u)

			if u.Path != tc.pathOut {
				t.Errorf("normalizePath(\"%s\"); expected %q, got %q", tc.pathIn, tc.pathOut, u.Path)
			}
			if u.RawPath != "" {
				t.Errorf("Expected empty RawPath, got %q", u.RawPath)
			}
		})
	}
}
