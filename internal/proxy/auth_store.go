package proxy

type WhoamiResponse struct {
	// ModId is an identifier that changes each time the site is
	// modified (Locations or LoginNeeded page content changes). The
	// changed ModId allows to detect these changes and refresh the
	// cached content.
	ModId   int    `json:"modId"`
	ID      string `json:"id"`      // Unique identifier of the user.
	Email   string `json:"email"`   // Email of the user
	IsAdmin bool   `json:"isAdmin"` // True if the user can access the site admin
}

type LocationsResponse struct {
	// See ModId comment in WhoamiResponse. When WhoamiResponse contains
	// ModId different than the one returned in LocationsResponse, it
	// indicates that LocationsResponse could have changed and
	// needs to be refreshed.
	ModId     int        `json:"modId"`
	Locations []Location `json:"locations"`
}

type AuthStore interface {
	// Whoami returns information about the user based on their cookie.
	// If the user is not authenticated (cookie is not recognized),
	// Whoami still returns WhoamiResponse with ID and Email set to ''
	// (no error is returned in such case).
	// Returns an error if the user information cannot be retrieved.
	Whoami(cookie string) (*WhoamiResponse, error)

	// Locations returns a list of site locations for which access
	// control rules are defined.
	// Returns an error if the locations cannot be retrieved.
	Locations() (*LocationsResponse, error)

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
