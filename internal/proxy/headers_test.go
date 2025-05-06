package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAcceptsHTML(t *testing.T) {
	tests := []struct {
		name         string
		acceptHeader string
		expected     bool
	}{
		{
			name:         "only text/html",
			acceptHeader: "text/html",
			expected:     true,
		},
		{
			name:         "text/html with quality",
			acceptHeader: "text/html; q=0.9",
			expected:     true,
		},
		{
			name:         "text/html among others",
			acceptHeader: "application/json, text/html, */*",
			expected:     true,
		},
		{
			name:         "wildcard",
			acceptHeader: "*/*",
			expected:     true,
		},
		{
			name:         "wildcard with quality",
			acceptHeader: "*/*; q=0.8",
			expected:     true,
		},
		{
			name:         "json only",
			acceptHeader: "application/json",
			expected:     false,
		},
		{
			name:         "multiple formats without html",
			acceptHeader: "application/json, application/xml, text/plain",
			expected:     false,
		},
		{
			name:         "empty header",
			acceptHeader: "",
			expected:     false,
		},
		{
			name:         "with whitespace",
			acceptHeader: " text/html , application/json ",
			expected:     true,
		},
		{
			name:         "with internal whitespace",
			acceptHeader: " text /   html",
			expected:     false,
		},
		{
			name:         "case insensitive",
			acceptHeader: "TEXT/HTML",
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Accept", tt.acceptHeader)
			if got := AcceptsHTML(req); got != tt.expected {
				t.Errorf("AcceptsHTML(%q) = %v, expected %v", tt.acceptHeader, got, tt.expected)
			}
		})
	}
}
