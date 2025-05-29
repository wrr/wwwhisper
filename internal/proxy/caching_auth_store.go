// caching_auth_store provides implementation of the AuthStore which
// wraps the real AuthStore and caches data to limit communication
// with it.
package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/wrr/wwwhispergo/internal/proxy/response"
)

const locationValidity = 5 * time.Minute

const sessionCacheValidity = 5 * time.Minute

const pageCacheValidity = 5 * time.Minute

// user entry is about 150B, which limits the cache size to ~1MB
const usersCacheSize = 10000

// See github.com/wrr/wwwhispergo/internal/timer
type Timer interface {
	Expired() bool
	Start()
}

// TimerFactory creates a timer. Allows to use fake timers in tests.
// Created timer is not started, Start() must be called before the
// first call to Expired().
type TimerFactory func(time.Duration) Timer

// A cacheEntry is a structure that hold hashed data of type T.
type cacheEntry[T any] struct {
	// Timer that counts time to the cachEntry data expiration.
	timer Timer
	value T // Cached data
	// True if the data was marked as stalled. Data can be stalled even
	// if the timer has not yet expired.
	stalled bool
}

// Get returns the cached data and a bool information if it was marked
// as stalled or the cache timer has expired.
func (c *cacheEntry[T]) Get() (T, bool) {
	stalled := c.stalled || c.timer.Expired()
	return c.value, stalled
}

// Sets the cached data. Restarts the timer and marks the entry as not
// stalled.
func (c *cacheEntry[T]) Set(v T) {
	c.value = v
	c.stalled = false
	c.timer.Start()
}

// Marks the cached data as stalled.
func (c *cacheEntry[T]) MarkStalled() {
	c.stalled = true
}

func newCacheEntry[T any](timer Timer) *cacheEntry[T] {
	return &cacheEntry[T]{
		timer:   timer,
		stalled: true,
	}
}

// A cachingAuthStore is a wrapper (decorator) around an AuthStore,
// exposing the same interface. It caches results returned by the auth
// store to limit the frequency of communication with the auth store.
//
// The cached content is refreshed once a timer associated with the
// cacheEntry expire, or when response.Whoami incoming from the
// authStore has modId different from the previously received modId.
type cachingAuthStore struct {
	// The wrapped AuthStore which provides the actual data.
	authStore AuthStore
	// Creates new timers which are then used to determine when cache
	// entries should be refreshed.
	newTimer TimerFactory
	log      *slog.Logger
	mu       sync.RWMutex
	// Maps a hashed user cookie to the whoami data for the user.
	users *lru.Cache[string, *cacheEntry[*response.Whoami]]

	// Last locationsResponse received from the authStore.
	locationsResponse cacheEntry[*response.Locations]
	// Last loginNeeded page received from the authStore.
	loginNeededPage cacheEntry[string]
	// Last forbidden page received from the authStore.
	forbiddenPage cacheEntry[string]
}

func NewCachingAuthStore(authStore AuthStore, newTimer TimerFactory, log *slog.Logger) *cachingAuthStore {
	return newCachingAuthStoreWithSize(authStore, newTimer, usersCacheSize, log)
}

// A separate function to allow for cache eviction testing.
func newCachingAuthStoreWithSize(authStore AuthStore, newTimer TimerFactory, cacheSize int, log *slog.Logger) *cachingAuthStore {
	usersCache, err := lru.New[string, *cacheEntry[*response.Whoami]](cacheSize)
	if err != nil {
		// This should never happen with positive cache size
		panic(err)
	}

	return &cachingAuthStore{
		authStore:         authStore,
		newTimer:          newTimer,
		log:               log,
		users:             usersCache,
		locationsResponse: *newCacheEntry[*response.Locations](newTimer(locationValidity)),
		loginNeededPage:   *newCacheEntry[string](newTimer(pageCacheValidity)),
		forbiddenPage:     *newCacheEntry[string](newTimer(pageCacheValidity)),
	}
}

func secureHash(cookie string) string {
	h := sha256.New()
	h.Write([]byte(cookie))
	return hex.EncodeToString(h.Sum(nil))
}

// Must be called with c.mu hold for writing.
func (c *cachingAuthStore) checkFreshness(modId int) {
	if c.locationsResponse.value == nil {
		// Locations not yet retrieved.
		return
	}

	if c.locationsResponse.value.ModId != modId {
		c.locationsResponse.MarkStalled()
		c.loginNeededPage.MarkStalled()
		c.forbiddenPage.MarkStalled()
	} else {
		// The site hasn't changed, reset the locations cache timers
		//
		// Note: loginNeededPage and forbiddenPage timers are not reset,
		// because these can change also when new wwwhisper version is
		// deployed, not only when the site changes.
		c.locationsResponse.timer.Start()
	}
}

func logCacheHit(ctx context.Context) {
	logger := GetRequestLogger(ctx)
	if logger != nil {
		logger.CacheHit()
	}
}

func logCacheHitStalled(ctx context.Context) {
	logger := GetRequestLogger(ctx)
	if logger != nil {
		logger.CacheHitStalled()
	}
}

func logCacheMiss(ctx context.Context) {
	logger := GetRequestLogger(ctx)
	if logger != nil {
		logger.CacheMiss()
	}
}

// See the AuthStore interface comments. cachingAuthStore.Whoami
// Returns cached response if it is not expired or if a request to get
// a fresh Whoami response fails. Error is returned only if the first
// request to retrieve the Whoami response fails.
//
// If response.Whoami contains modId different from the modId of the
// currently cached locationsResponse, marks cached locations, login
// and forbidden pages as stalled (modId indicates that the site
// configuration was modified).
func (c *cachingAuthStore) Whoami(ctx context.Context, cookie string) (*response.Whoami, error) {
	// Hash the cookie to prevent cache lookup timing attacks
	hashedCookie := secureHash(cookie)
	// LRU cache is thread safe.
	cacheEntry, ok := c.users.Get(hashedCookie)
	var respCached *response.Whoami
	if ok {
		var stalled bool
		respCached, stalled = cacheEntry.Get()
		if !stalled {
			logCacheHit(ctx)
			return respCached, nil
		}
	}
	freshResp, err := c.authStore.Whoami(ctx, cookie)
	if err != nil {
		if respCached != nil {
			// If failed to obtain a fresh response, but stalled cached
			// response exists, return it.
			logCacheHitStalled(ctx)
			return respCached, nil
		}
		return nil, err
	}
	// Lock because modification of cacheEntry is not thread safe.
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkFreshness(freshResp.ModId)
	if !ok {
		cacheEntry = newCacheEntry[*response.Whoami](c.newTimer(sessionCacheValidity))
		c.users.Add(hashedCookie, cacheEntry)
	}
	cacheEntry.Set(freshResp)
	logCacheMiss(ctx)
	return freshResp, nil
}

// See the AuthStore interface comments. If cached location data is
// stalled, attempts to refresh it, but fallbacks to stalled location
// data if the refresh request fails. Error is returned only if the
// first request to get locations fails.
func (c *cachingAuthStore) Locations(ctx context.Context) (*response.Locations, error) {
	c.mu.RLock()
	resp, stalled := c.locationsResponse.Get()
	c.mu.RUnlock()
	if stalled {
		// TODO: some retry mechanism?
		freshResp, err := c.authStore.Locations(ctx)
		if err != nil {
			c.log.Warn(err.Error())
			if resp != nil {
				logCacheHitStalled(ctx)
				return resp, nil
			}
			return nil, err
		}
		c.mu.Lock()
		c.locationsResponse.Set(freshResp)
		c.mu.Unlock()
		resp = freshResp
		logCacheMiss(ctx)
	} else {
		logCacheHit(ctx)
	}
	return resp, nil
}

type getFresh func(context.Context) (string, error)

func (c *cachingAuthStore) getPage(ctx context.Context, entry *cacheEntry[string], fresh getFresh) (string, error) {
	c.mu.RLock()
	page, stalled := entry.Get()
	c.mu.RUnlock()
	if stalled {
		freshPage, err := fresh(ctx)
		if err != nil {
			c.log.Warn(err.Error())
			// If page failed to refresh, return error only if stalled
			// version doesn't exist.
			if page == "" {
				return "", err
			}
			logCacheHitStalled(ctx)
		} else {
			c.mu.Lock()
			entry.Set(freshPage)
			c.mu.Unlock()
			page = freshPage
			logCacheMiss(ctx)
		}
	} else {
		logCacheHit(ctx)
	}
	return page, nil
}

// See the AuthStore interface comments.
func (c *cachingAuthStore) LoginNeededPage(ctx context.Context) (string, error) {
	return c.getPage(ctx, &c.loginNeededPage, c.authStore.LoginNeededPage)
}

// See the AuthStore interface comments.
func (c *cachingAuthStore) ForbiddenPage(ctx context.Context) (string, error) {
	return c.getPage(ctx, &c.forbiddenPage, c.authStore.ForbiddenPage)

}
