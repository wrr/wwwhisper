package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/wrr/wwwhispergo/internal/proxy/response"
)

// TODO: Shorter, but bump with each whoami response
const locationValidity = 10 * time.Minute

// TODO: extend
const sessionCacheValidity = 10 * time.Minute

// TODO: Shorter, but bump with each whoami response
const pageCacheValidity = 10 * time.Minute

type Timer interface {
	Expired() bool
	Start()
}

type TimerFactory func(time.Duration) Timer

type cacheEntry[T any] struct {
	timer   Timer
	value   T
	stalled bool
}

func (c *cacheEntry[T]) Get() (T, bool) {
	stalled := c.stalled || c.timer.Expired()
	return c.value, stalled
}

func (c *cacheEntry[T]) Set(v T) {
	c.value = v
	c.stalled = false
	c.timer.Start()
}

func (c *cacheEntry[T]) MarkStalled() {
	c.stalled = true
}

func NewCacheEntry[T any](timer Timer) *cacheEntry[T] {
	return &cacheEntry[T]{
		timer:   timer,
		stalled: true,
	}
}

type cachingAuthStore struct {
	authStore         AuthStore
	newTimer          TimerFactory
	log               *slog.Logger
	users             map[string]*cacheEntry[*response.Whoami]
	locationsResponse cacheEntry[*response.Locations]
	loginNeededPage   cacheEntry[string]
	forbiddenPage     cacheEntry[string]
}

func NewCachingAuthStore(authStore AuthStore, newTimer TimerFactory, log *slog.Logger) *cachingAuthStore {
	return &cachingAuthStore{
		authStore:         authStore,
		newTimer:          newTimer,
		log:               log,
		users:             make(map[string]*cacheEntry[*response.Whoami]),
		locationsResponse: *NewCacheEntry[*response.Locations](newTimer(locationValidity)),
		loginNeededPage:   *NewCacheEntry[string](newTimer(pageCacheValidity)),
		forbiddenPage:     *NewCacheEntry[string](newTimer(pageCacheValidity)),
	}
}

func secureHash(cookie string) string {
	h := sha256.New()
	h.Write([]byte(cookie))
	return hex.EncodeToString(h.Sum(nil))
}

func (c *cachingAuthStore) checkFreshness(modId int) {
	if c.locationsResponse.value == nil {
		return
	}

	if c.locationsResponse.value.ModId != modId {
		c.locationsResponse.MarkStalled()
		c.loginNeededPage.MarkStalled()
		c.forbiddenPage.MarkStalled()
	} else {
		// Reset the cached entries timers
		c.locationsResponse.timer.Start()
		if c.loginNeededPage.value != "" {
			c.loginNeededPage.timer.Start()
		}
		if c.forbiddenPage.value != "" {
			c.forbiddenPage.timer.Start()
		}
	}
}

func (c *cachingAuthStore) Whoami(cookie string) (*response.Whoami, error) {
	// hashCookie to prevent cache lookup timing attacks
	hashedCookie := secureHash(cookie)
	cacheEntry, ok := c.users[hashedCookie]
	var respCached *response.Whoami
	if ok {
		var stalled bool
		respCached, stalled = cacheEntry.Get()
		if !stalled {
			return respCached, nil
		}
	}
	freshResp, err := c.authStore.Whoami(cookie)
	if err != nil {
		if respCached != nil {
			// If failed to obtain a fresh response, but stalled cached
			// response exists, return it.
			return respCached, nil
		}
		return nil, err
	}
	c.checkFreshness(freshResp.ModId)
	if !ok {
		// TODO: limit cache size.
		cacheEntry = NewCacheEntry[*response.Whoami](c.newTimer(sessionCacheValidity))
		c.users[hashedCookie] = cacheEntry
	}
	cacheEntry.Set(freshResp)
	return freshResp, nil
}

func (c *cachingAuthStore) Locations() (*response.Locations, error) {
	resp, stalled := c.locationsResponse.Get()
	if stalled {
		// TODO: some retry mechanis?
		freshResp, err := c.authStore.Locations()
		if err != nil {
			c.log.Warn(err.Error())
			if resp != nil {
				return resp, nil
			}
			return nil, err
		}
		c.locationsResponse.Set(freshResp)
		resp = freshResp
	}
	return resp, nil
}

func (c *cachingAuthStore) LoginNeededPage() (string, error) {
	page, stalled := c.loginNeededPage.Get()
	if stalled {
		freshPage, err := c.authStore.LoginNeededPage()
		if err != nil {
			c.log.Warn(err.Error())
			// If page failed to refresh, return error only if stalled
			// version doesn't exist.
			if page == "" {
				return "", err
			}
		} else {
			c.loginNeededPage.Set(freshPage)
			page = freshPage
		}
	}
	return page, nil
}

func (c *cachingAuthStore) ForbiddenPage() (string, error) {
	page, stalled := c.forbiddenPage.Get()
	if stalled {
		freshPage, err := c.authStore.ForbiddenPage()
		if err != nil {
			c.log.Warn(err.Error())
			// If page failed to refresh, return error only if stalled
			// version doesn't exist.
			if page == "" {
				return "", err
			}
		} else {
			c.forbiddenPage.Set(freshPage)
			page = freshPage
		}
	}
	return page, nil
}
