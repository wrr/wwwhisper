// Copyright (C) 2025 Jan Wrobel <jan@wwwhisper.io>
// This program is freely distributable under the terms of the
// Simplified BSD License. See COPYING.

package proxy

import (
	"net/http"
	"strings"
)

// AcceptsHTML checks if the HTTP request accepts HTML responses by
// examining the "Accept" header in the request.
func AcceptsHTML(r *http.Request) bool {
	acceptHeader := r.Header.Get("Accept")
	if acceptHeader == "" {
		return false
	}
	mediaTypes := strings.Split(acceptHeader, ",")
	for _, mediaType := range mediaTypes {
		// Trim any whitespace and parameters (e.g., "text/html; q=0.9")
		mediaType = strings.TrimSpace(strings.Split(mediaType, ";")[0])
		mediaType = strings.ToLower(mediaType)
		if mediaType == "text/html" || mediaType == "*/*" {
			return true
		}
	}
	return false
}
