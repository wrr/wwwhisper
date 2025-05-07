package proxy

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
