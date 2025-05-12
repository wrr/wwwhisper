package proxy

import "github.com/wrr/wwwhispergo/internal/proxy/response"

type AuthStore interface {
	// Whoami returns information about the user based on their cookie.
	// If the user is not authenticated (cookie is not recognized),
	// Whoami still returns response.Whoami with ID and Email set to ''
	// (no error is returned in such case).
	// Returns an error if the user information cannot be retrieved.
	Whoami(cookie string) (*response.Whoami, error)

	// Locations returns a list of site locations for which access
	// control rules are defined.
	// Returns an error if the locations cannot be retrieved.
	Locations() (*response.Locations, error)

	// LoginNeededPage returns the HTML content of a login page. The
	// page should be returned to users that try to access protected
	// location, but are not authenticated.
	// Returns an error if the page cannot be retrieved.
	LoginNeededPage() (string, error)

	// ForbiddenPage returns the HTML content of an access forbidden
	// page. The page should be returned to authenticated users that try
	// to access protected location to which they are not granted
	// access.
	// Returns an error if the page cannot be retrieved.
	ForbiddenPage() (string, error)
}
