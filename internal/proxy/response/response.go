package response

import (
	"strings"
)

type User struct {
	Email string `json:"email"`
	Self  string `json:"self"`
	ID    string `json:"id"`
}

type Location struct {
	Path         string `json:"path"`
	OpenAccess   bool   `json:"openAccess"`
	AllowedUsers []User `json:"allowedUsers"`
	Self         string `json:"self"`
	ID           string `json:"id"`
}

type Whoami struct {
	// ModId is an identifier that changes each time the site is
	// modified (Locations or LoginNeeded page content changes). The
	// changed ModId allows to detect these changes and refresh the
	// cached content.
	ModId   int    `json:"modId"`
	ID      string `json:"id"`      // Unique identifier of the user.
	Email   string `json:"email"`   // Email of the user
	IsAdmin bool   `json:"isAdmin"` // True if the user can access the site admin
}

type Locations struct {
	// See ModId comment in response.Whoami. When response.Whoami
	// contains ModId different than the one returned in
	// response.Locations, it indicates that qLocations could have
	// changed and needs to be refreshed.
	ModId   int        `json:"modId"`
	Entries []Location `json:"locations"`
}

// Can access check if the user with the given userId can access the
// location.
func (l *Location) CanAccess(userId string) bool {
	if l.OpenAccess {
		return true
	}
	for _, user := range l.AllowedUsers {
		if user.ID == userId {
			return true
		}
	}
	return false
}

// MatchingLocation finds a location that defines access to a given
// path on the site.  The path argument must be in canonical format
// (absolute and normalized).  The function returns the most specific
// location with path matching a given path or None if no matching
// location exists.
func MatchingLocation(locations []Location, path string) *Location {
	// TODO: or maybe better make it a method on response.Locations
	longestMatched := (*Location)(nil)
	longestMatchedLen := -1
	pathLen := len(path)

	for i := range locations {
		location := &locations[i]
		probedPath := location.Path
		if !strings.HasPrefix(path, probedPath) {
			continue
		}
		probedPathLen := len(probedPath)
		if probedPathLen <= longestMatchedLen {
			continue
		}

		var slashIndex int
		if strings.HasSuffix(probedPath, "/") {
			slashIndex = probedPathLen - 1
		} else {
			slashIndex = probedPathLen
		}

		if probedPathLen == pathLen || path[slashIndex] == '/' {
			longestMatched = location
			longestMatchedLen = probedPathLen
		}
	}

	return longestMatched
}
