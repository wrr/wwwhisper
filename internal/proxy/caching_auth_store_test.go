package proxy

import (
	"context"
	"fmt"
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
	startCalled   int
}

func (ft *fakeTimer) Expired() bool {
	ft.t.Helper()
	if ft.startCalled == 0 {
		ft.t.Fatalf("Accessing not started timer")
	}
	return ft.expiredReturn
}

func (ft *fakeTimer) Start() {
	ft.startCalled += 1
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

func newCASDeps(t *testing.T) (context.Context, *proxytest.AuthServer, *fakeTimer, *cachingAuthStore) {
	authServer := proxytest.NewAuthServer(t)
	logger := proxytest.NewLogger()
	remoteStore := NewRemoteAuthStore(authServer.URL, logger)
	timer := NewFakeTimer(t, false)
	cachingStore := NewCachingAuthStore(remoteStore, timer.factory, logger)
	return context.Background(), authServer, timer, cachingStore
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

func check[T any](resp T, err error, expectedResp T, expectedErr string) error {
	if err != nil {
		if expectedErr == "" {
			return fmt.Errorf("unexpected error %v", err)
		}
		if !strings.Contains(err.Error(), expectedErr) {
			return fmt.Errorf("unexpected error %v vs %v", err, expectedErr)
		}
		return nil
	}
	if expectedErr != "" {
		return fmt.Errorf("expected error not returned %v", expectedErr)
	}
	if !reflect.DeepEqual(resp, expectedResp) {
		return fmt.Errorf("unexpected result %#v vs %#v", resp, expectedResp)
	}
	return nil
}

func TestCachingAuthStore_Whoami(t *testing.T) {
	ctx, authServer, timer, cachingStore := newCASDeps(t)
	defer authServer.Close()

	// First request to get the user fails, error should be propageted.
	authServer.StatusCode = 507
	resp, err := cachingStore.Whoami(ctx, "alice-cookie")
	if err = check(resp, err, nil, "whoami failed: 507"); err != nil {
		t.Error(err)
	}

	authServer.StatusCode = 200
	resp, err = cachingStore.Whoami(ctx, "alice-cookie")
	expected := *authServer.Users["alice-cookie"]
	expected.ModId = authServer.ModId
	if err = check(resp, err, &expected, ""); err != nil {
		t.Error(err)
	}

	// New user data is available, but the cache is not stalled, so
	// still returns the old version.
	authServer.Users["alice-cookie"].Email = "alice@new-example.org"
	resp, err = cachingStore.Whoami(ctx, "alice-cookie")
	if err = check(resp, err, &expected, ""); err != nil {
		t.Error(err)
	}

	// If the cache is stalled, but the request to refresh if fails, the
	// old version of user data should be returned
	timer.expiredReturn = true
	authServer.StatusCode = 507
	resp, err = cachingStore.Whoami(ctx, "alice-cookie")
	if err = check(resp, err, &expected, ""); err != nil {
		t.Error(err)
	}

	// Now the cache should refresh successfully.
	authServer.StatusCode = 200
	resp, err = cachingStore.Whoami(ctx, "alice-cookie")
	expected.Email = "alice@new-example.org"
	if err = check(resp, err, &expected, ""); err != nil {
		t.Error(err)
	}
}

func TestCachingAuthStore_Locations(t *testing.T) {
	ctx, authServer, timer, cachingStore := newCASDeps(t)
	defer authServer.Close()

	// First request to get the locations fails, error should be propageted.
	authServer.StatusCode = 507
	locations, err := cachingStore.Locations(ctx)
	if err = check(locations, err, nil, "get locations failed: 507"); err != nil {
		t.Error(err)
	}

	authServer.StatusCode = 200
	locations, err = cachingStore.Locations(ctx)
	expected := response.Locations{
		ModId:   authServer.ModId,
		Entries: make([]response.Location, len(authServer.Locations)),
	}
	copy(expected.Entries, authServer.Locations)
	if err = check(locations, err, &expected, ""); err != nil {
		t.Error(err)
	}

	// New version of locations is available, but the cache is not
	// stalled so still returns the old version
	authServer.Locations[0].Path = "/new-root"
	locations, err = cachingStore.Locations(ctx)
	if err = check(locations, err, &expected, ""); err != nil {
		t.Error(err)
	}

	// If the cache is stalled, but the request to refresh if fails, the
	// old version of the locations should be returned.
	timer.expiredReturn = true
	authServer.StatusCode = 507
	locations, err = cachingStore.Locations(ctx)
	if err = check(locations, err, &expected, ""); err != nil {
		t.Error(err)
	}

	// Now the cache should refresh successfully.
	authServer.StatusCode = 200
	locations, err = cachingStore.Locations(ctx)
	expected.Entries[0].Path = "/new-root"
	if err = check(locations, err, &expected, ""); err != nil {
		t.Error(err)
	}
}

func TestCachingAuthStore_LoginNeededPage(t *testing.T) {
	ctx, authServer, timer, cachingStore := newCASDeps(t)
	defer authServer.Close()

	// First request to get the page fails, error should be propageted.
	authServer.StatusCode = 507
	page, err := cachingStore.LoginNeededPage(ctx)
	if err = check(page, err, "", "get /api/login-needed/ failed: 507"); err != nil {
		t.Error(err)
	}

	authServer.StatusCode = 200
	page, err = cachingStore.LoginNeededPage(ctx)
	if err = check(page, err, authServer.LoginNeeded, ""); err != nil {
		t.Error(err)
	}

	// New version of a page is available, but the cache is not stalled
	// so still returns the old version
	origPage := authServer.LoginNeeded
	newPage := "new version of a  page"
	authServer.LoginNeeded = newPage
	if err = check(page, err, origPage, ""); err != nil {
		t.Error(err)
	}

	// If the cache is stalled, but the request to refresh if fails, the
	// old version of the page should be returned.
	timer.expiredReturn = true
	authServer.StatusCode = 507
	if err = check(page, err, origPage, ""); err != nil {
		t.Error(err)
	}

	// Now the cache should refresh successfully.
	authServer.StatusCode = 200
	page, err = cachingStore.LoginNeededPage(ctx)
	if err = check(page, err, newPage, ""); err != nil {
		t.Error(err)
	}
}

func TestCachingAuthStore_ForbiddenPage(t *testing.T) {
	ctx, authServer, timer, cachingStore := newCASDeps(t)
	defer authServer.Close()

	// First request to get the page fails, error should be propageted.
	authServer.StatusCode = 507
	page, err := cachingStore.ForbiddenPage(ctx)
	if err = check(page, err, "", "get /api/forbidden/ failed: 507"); err != nil {
		t.Error(err)
	}

	authServer.StatusCode = 200
	page, err = cachingStore.ForbiddenPage(ctx)
	if err = check(page, err, authServer.Forbidden, ""); err != nil {
		t.Error(err)
	}

	// New version of a page is available, but the cache is not stalled
	// so still returns the old version
	origPage := authServer.Forbidden
	newPage := "new version of a  page"
	authServer.Forbidden = newPage
	page, err = cachingStore.ForbiddenPage(ctx)
	if err = check(page, err, origPage, ""); err != nil {
		t.Error(err)
	}

	// If the cache is stalled, but the request to refresh if fails, the
	// old version of the page should be returned.
	timer.expiredReturn = true
	authServer.StatusCode = 507
	page, err = cachingStore.ForbiddenPage(ctx)
	if err = check(page, err, origPage, ""); err != nil {
		t.Error(err)
	}

	// Now the cache should refresh successfully.
	authServer.StatusCode = 200
	page, err = cachingStore.ForbiddenPage(ctx)
	if err = check(page, err, newPage, ""); err != nil {
		t.Error(err)
	}
}

func TestCachingAuthStore_ModIdTriggersCacheRefresh(t *testing.T) {
	ctx, authServer, timer, cachingStore := newCASDeps(t)
	defer authServer.Close()

	checkResponses := func(loginNeeded string, forbidden string, locations *response.Locations) {
		t.Helper()
		page, err := cachingStore.LoginNeededPage(ctx)
		if err = check(page, err, loginNeeded, ""); err != nil {
			t.Error(err)
		}
		page, err = cachingStore.ForbiddenPage(ctx)
		if err = check(page, err, forbidden, ""); err != nil {
			t.Error(err)
		}
		l, err := cachingStore.Locations(ctx)
		if err = check(l, err, locations, ""); err != nil {
			t.Error(err)
		}
	}

	origLoginNeeded := authServer.LoginNeeded
	origForbidden := authServer.Forbidden
	locations := &response.Locations{
		ModId:   authServer.ModId,
		Entries: make([]response.Location, len(authServer.Locations)),
	}
	copy(locations.Entries, authServer.Locations)

	checkResponses(origLoginNeeded, origForbidden, locations)
	if timer.startCalled != 3 {
		// Each cached entry should have a separate timer.
		t.Error("Unexpected timer starts", timer.startCalled)
	}

	// New version of cached content is available, but the cache is not stalled
	// so still returns the old version
	authServer.Forbidden = "new forbidden page"
	authServer.LoginNeeded = "new login needed page"
	authServer.Locations[0].Path = "/new-root"
	checkResponses(origLoginNeeded, origForbidden, locations)

	// whoami response with the same modId should not trigger the cache
	// refresh.
	_, _ = cachingStore.Whoami(ctx, "alice-cookie")
	checkResponses(origLoginNeeded, origForbidden, locations)
	// Whoami response with the same ModId should restart locations
	// timer and start a new timer for the user entry.
	if timer.startCalled != 5 {
		t.Error("Unexpected timer starts", timer.startCalled)
	}

	// whoami response with different modId should trigger the cache
	// refresh.
	authServer.ModId += 1
	_, _ = cachingStore.Whoami(ctx, "bob-cookie")
	locations.Entries[0].Path = "/new-root"
	locations.ModId = authServer.ModId
	checkResponses(authServer.LoginNeeded, authServer.Forbidden, locations)

	if timer.startCalled != 9 {
		t.Error("Unexpected timer starts", timer.startCalled)
	}
}
