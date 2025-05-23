package proxy

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/wrr/wwwhispergo/internal/proxy/response"
)

// AccessGuard determines whether incoming HTTP requests should be
// allowed and processed further. It uses authentication and
// authorization data from the AuthStore. If a request is
// unauthorized, it writes an appropriate HTTP error response and
// blocks further processing.
type accessGuard struct {
	authStore AuthStore // Provides auth data for the accessGuard
	log       *slog.Logger
}

func NewAccessGuard(c AuthStore, log *slog.Logger) *accessGuard {
	return &accessGuard{
		authStore: c,
		log:       log,
	}
}

func (g *accessGuard) loginNeeded(rw http.ResponseWriter, req *http.Request) {
	status := http.StatusUnauthorized
	GetRequestLogger(req.Context()).HttpStatus(status)
	if AcceptsHTML(req) {
		if page, err := g.authStore.LoginNeededPage(req.Context()); err == nil {
			// no error.
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
			rw.WriteHeader(status)
			rw.Write([]byte(page))
			return
		}
	}
	http.Error(rw, "Authentication required.", status)
}

func (g *accessGuard) forbidden(rw http.ResponseWriter, req *http.Request) {
	status := http.StatusForbidden
	GetRequestLogger(req.Context()).HttpStatus(status)
	if AcceptsHTML(req) {
		if page, err := g.authStore.ForbiddenPage(req.Context()); err == nil {
			// no error.
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
			rw.WriteHeader(status)
			rw.Write([]byte(page))
			return
		}
	}
	http.Error(rw, "Access forbidden.", status)
}

func (g *accessGuard) internalError(rw http.ResponseWriter, req *http.Request, err error) {
	status := http.StatusInternalServerError
	GetRequestLogger(req.Context()).HttpStatus(status)
	g.log.Warn("wwwhisper", "error", err)
	http.Error(rw, "Internal server error (auth)", status)
}

// Handle allows or rejects an incoming HTTP request. It returns true
// if the request is allowed, in such case it can be further
// processed. Handle adds a User header to the allowed requests with
// an email address of the authenticated user (if any). It also
// normalizes the incoming request path, the caller must then use the
// path from the req to route the request, not the original, not
// normalized version.
//
// Handle returns false for not allowed requests, in such case it also
// writes an appropriate HTTP error response (401 for not
// authenticated requests, 403 for not authorized requests, 500 in
// case authorization data can not be obtained temporarily).
func (g *accessGuard) Handle(rw http.ResponseWriter, req *http.Request) bool {
	normalizePath(req.URL)

	// If the client is trying to pass the User header, delete it.
	req.Header.Del("User")

	var err error

	if strings.HasPrefix(req.URL.Path, "/wwwhisper/auth/") {
		// login/logout/send-token etc. always allowed, doesn't require authentication.
		return true
	}

	var whoami *response.Whoami
	cookie, _ := req.Cookie("wwwhisper-sessionid")
	if cookie != nil {
		whoami, err = g.authStore.Whoami(req.Context(), cookie.Value)
		if err != nil {
			g.internalError(rw, req, err)
			return false
		}
	}

	locationsResponse, err := g.authStore.Locations(req.Context())
	if err != nil {
		g.internalError(rw, req, err)
		return false
	}

	location := locationsResponse.LongestMatch(req.URL.Path)
	if location == nil {
		g.forbidden(rw, req)
		return false
	}
	userID := ""
	if whoami != nil {
		userID = whoami.ID
	}
	if location.CanAccess(userID) {
		if whoami != nil && whoami.Email != "" {
			req.Header.Add("User", whoami.Email)
		}
		return true
	}
	if userID == "" {
		g.loginNeeded(rw, req)
	} else {
		g.forbidden(rw, req)
	}
	return false
}
