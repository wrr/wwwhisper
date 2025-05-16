package proxy

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wrr/wwwhispergo/internal/proxy/response"
	"github.com/wrr/wwwhispergo/internal/proxytest"
)

type fakeTimer struct {
	t             *testing.T
	expiredReturn bool
	factory       func(time.Duration) Timer
	startCalled   bool
}

func (ft *fakeTimer) Expired() bool {
	ft.t.Helper()
	if !ft.startCalled {
		ft.t.Fatalf("Accessing not started timer")
	}
	return ft.expiredReturn
}

func (ft *fakeTimer) Start() {
	ft.startCalled = true
}

func NewFakeTimer(t *testing.T, expired bool) *fakeTimer {
	// Doesn't seem to have any effect...
	t.Helper()
	ft := &fakeTimer{
		t:             t,
		expiredReturn: expired,
	}
	ft.factory = func(time.Duration) Timer {
		return ft
	}
	return ft
}

func TestSecureHash(t *testing.T) {
	hash1 := secureHash("test-cookie")
	hash2 := secureHash("test-cookie")
	hash3 := secureHash("different-cookie")

	if hash1 != hash2 {
		t.Error("Same cookie should produce same hash")
	}
	if hash1 == hash3 {
		t.Error("Different cookies should produce different hashes")
	}
	if len(hash1) != 64 {
		t.Errorf("SHA-256 hash should be 64 hex characters, got %d", len(hash1))
	}
}

func TestCachingAuthStore_Whoami(t *testing.T) {
	authServer := proxytest.NewAuthServer(t)
	defer authServer.Close()

	remoteStore := NewRemoteAuthStore(authServer.URL)
	timer := NewFakeTimer(t, false)
	logger := proxytest.NewLogger()
	cachingStore := NewCachingAuthStore(remoteStore, timer.factory, logger)

	// First request to get the user fails, error should be propageted.
	authServer.StatusCode = 507
	_, err := cachingStore.Whoami("alice-cookie")
	if err == nil || !strings.Contains(err.Error(), "whoami failed: 507") {
		t.Errorf("Unexpected error %v", err)
	}

	authServer.StatusCode = 200
	resp, err := cachingStore.Whoami("alice-cookie")
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	expected := *authServer.Users["alice-cookie"]
	expected.ModId = authServer.ModId

	if !reflect.DeepEqual(*resp, expected) {
		t.Errorf("Unexpected response %#v vs %#v", *resp, expected)
	}

	// New user data is available, but the cache is not stalled, so
	// still returns the old version.
	authServer.Users["alice-cookie"].Email = "alice@new-example.org"
	resp, err = cachingStore.Whoami("alice-cookie")
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if !reflect.DeepEqual(*resp, expected) {
		t.Errorf("Unexpected response %#v vs %#v", *resp, expected)
	}

	// If the cache is stalled, but the request to refresh if fails, the
	// old version of user data should be returned
	timer.expiredReturn = true
	authServer.StatusCode = 507
	resp, err = cachingStore.Whoami("alice-cookie")
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if !reflect.DeepEqual(*resp, expected) {
		t.Errorf("Unexpected response %#v vs %#v", *resp, expected)
	}

	// Now the cache should refresh successfully.
	authServer.StatusCode = 200
	resp, err = cachingStore.Whoami("alice-cookie")
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	expected.Email = "alice@new-example.org"
	if !reflect.DeepEqual(*resp, expected) {
		t.Errorf("Unexpected response %#v vs %#v", *resp, expected)
	}
}

func TestCachingAuthStore_Locations(t *testing.T) {
	authServer := proxytest.NewAuthServer(t)
	defer authServer.Close()

	// TODO: dedup this setup
	remoteStore := NewRemoteAuthStore(authServer.URL)
	timer := NewFakeTimer(t, false)
	logger := proxytest.NewLogger()
	cachingStore := NewCachingAuthStore(remoteStore, timer.factory, logger)

	// First request to get the locations fails, error should be propageted.
	authServer.StatusCode = 507
	_, err := cachingStore.Locations()
	if err == nil || !strings.Contains(err.Error(), "get locations failed: 507") {
		t.Errorf("Unexpected error %v", err)
	}

	authServer.StatusCode = 200
	locations, err := cachingStore.Locations()
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	expected := response.Locations{
		ModId:   authServer.ModId,
		Entries: make([]response.Location, len(authServer.Locations)),
	}
	copy(expected.Entries, authServer.Locations)

	if !reflect.DeepEqual(*locations, expected) {
		t.Errorf("Unexpected locations %v vs %v", locations, expected)
	}

	// New version of locations is available, but the cache is not
	// stalled so still returns the old version
	authServer.Locations[0].Path = "/new-root"
	locations, err = cachingStore.Locations()
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if !reflect.DeepEqual(*locations, expected) {
		t.Errorf("Unexpected locations %v vs %v", locations, expected)
	}

	// If the cache is stalled, but the request to refresh if fails, the
	// old version of the locations should be returned.
	timer.expiredReturn = true
	authServer.StatusCode = 507
	locations, err = cachingStore.Locations()
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if !reflect.DeepEqual(*locations, expected) {
		t.Errorf("Unexpected locations %v vs %v", locations, expected)
	}

	// Now the cache should refresh successfully.
	authServer.StatusCode = 200
	locations, err = cachingStore.Locations()
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	expected.Entries[0].Path = "/new-root"
	if !reflect.DeepEqual(*locations, expected) {
		t.Errorf("Unexpected locations %v vs %v", locations, expected)
	}
}

func TestCachingAuthStore_LoginNeededPage(t *testing.T) {
	authServer := proxytest.NewAuthServer(t)
	defer authServer.Close()

	remoteStore := NewRemoteAuthStore(authServer.URL)
	timer := NewFakeTimer(t, false)
	logger := proxytest.NewLogger()
	cachingStore := NewCachingAuthStore(remoteStore, timer.factory, logger)

	// First request to get the page fails, error should be propageted.
	authServer.StatusCode = 507
	_, err := cachingStore.LoginNeededPage()
	if err == nil || !strings.Contains(err.Error(), "get /api/login-needed/ failed: 507") {
		t.Errorf("Unexpected error %v", err)
	}

	authServer.StatusCode = 200
	page, err := cachingStore.LoginNeededPage()
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if page != authServer.LoginNeeded {
		t.Errorf("Unexpected page %s", page)
	}

	// New version of a page is available, but the cache is not stalled
	// so still returns the old version
	origPage := authServer.LoginNeeded
	newPage := "new version of a  page"
	authServer.LoginNeeded = newPage
	page, err = cachingStore.LoginNeededPage()
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if page != origPage {
		t.Errorf("Unexpected page %s", page)
	}

	// If the cache is stalled, but the request to refresh if fails, the
	// old version of the page should be returned.
	timer.expiredReturn = true
	authServer.StatusCode = 507
	page, err = cachingStore.LoginNeededPage()
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if page != origPage {
		t.Errorf("Unexpected page %s", page)
	}

	// Now the cache should refresh successfully.
	authServer.StatusCode = 200
	page, err = cachingStore.LoginNeededPage()
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if page != newPage {
		t.Errorf("Unexpected page %s", page)
	}
}

func TestCachingAuthStore_ForbiddenPage(t *testing.T) {
	authServer := proxytest.NewAuthServer(t)
	defer authServer.Close()

	remoteStore := NewRemoteAuthStore(authServer.URL)
	timer := NewFakeTimer(t, false)
	logger := proxytest.NewLogger()
	cachingStore := NewCachingAuthStore(remoteStore, timer.factory, logger)

	// First request to get the page fails, error should be propageted.
	authServer.StatusCode = 507
	_, err := cachingStore.ForbiddenPage()
	if err == nil || !strings.Contains(err.Error(), "get /api/forbidden/ failed: 507") {
		t.Errorf("Unexpected error %v", err)
	}

	authServer.StatusCode = 200
	page, err := cachingStore.ForbiddenPage()
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if page != authServer.Forbidden {
		t.Errorf("Unexpected page %s", page)
	}

	// New version of a page is available, but the cache is not stalled
	// so still returns the old version
	origPage := authServer.Forbidden
	newPage := "new version of a  page"
	authServer.Forbidden = newPage
	page, err = cachingStore.ForbiddenPage()
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if page != origPage {
		t.Errorf("Unexpected page %s", page)
	}

	// If the cache is stalled, but the request to refresh if fails, the
	// old version of the page should be returned.
	timer.expiredReturn = true
	authServer.StatusCode = 507
	page, err = cachingStore.ForbiddenPage()
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if page != origPage {
		t.Errorf("Unexpected page %s", page)
	}

	// Now the cache should refresh successfully.
	authServer.StatusCode = 200
	page, err = cachingStore.ForbiddenPage()
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if page != newPage {
		t.Errorf("Unexpected page %s", page)
	}
}
