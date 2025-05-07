package proxy

import (
	"net/url"
	"path"
	"strings"
)

func normalizePath(url *url.URL) {
	pathIn := url.Path
	pathOut := pathIn
	if !strings.HasPrefix(pathOut, "/") {
		pathOut = "/" + pathOut
	}
	pathOut = path.Clean(pathOut)
	if strings.HasSuffix(pathIn, "/") && !strings.HasSuffix(pathOut, "/") {
		pathOut += "/"
	}
	url.Path = pathOut
	// if RawPath is empty it is assumed to be equal to Path
	// (RequestURI() will just use Path and will not contain any escaped
	// elements).
	//
	// This approach makes it impossible to use wwwhisper for apps that
	// encode data in paths, paths are always authenticated and then
	// passed to the app as decoded, the information which parts were
	// encoded is lost. This is to ensure auth layer and app interpret
	// the path in the same way. For example a request to /admin/%2E%2E/
	// is normalized as the request to the root document /, and app never sees
	// the original /admin/%2E%2E/ path.
	url.RawPath = ""
}
