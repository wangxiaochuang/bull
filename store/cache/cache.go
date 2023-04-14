package cache

import (
	"context"
	"sync/atomic"

	v1 "github.com/zilicorp/bull/pkg/api/core/v1"
	"github.com/zilicorp/bull/pkg/lru"
	"github.com/zilicorp/bull/pkg/pathmanager"
	"github.com/zilicorp/bull/pkg/utils"
	"github.com/zilicorp/bull/store"
)

const (
	DefaultCacheSize   = 128 * 1024
	refreshCacheCtxKey = "refresh_cache"
)

var cacheExceptionsPaths = []string{
	"wal/logs/",
	"index/pages/",
	"index-dr/pages/",
	"sys/expire/",
	"core/poison-pill",
	"core/raft/tls",
}

func cacheRefreshFromContext(ctx context.Context) bool {
	r, ok := ctx.Value(refreshCacheCtxKey).(bool)
	if !ok {
		return false
	}
	return r
}

type Cache struct {
	store           store.Store
	lru             *lru.TwoQueueCache
	locks           []*utils.LockEntry
	enabled         *uint32
	cacheExceptions *pathmanager.PathManager
}

func NewCache(b store.Store, size int) *Cache {
	if size <= 0 {
		size = DefaultCacheSize
	}

	pm := pathmanager.New()
	pm.AddPaths(cacheExceptionsPaths)

	cache, _ := lru.New2Q(size)
	c := &Cache{
		store:           b,
		lru:             cache,
		locks:           utils.CreateLocks(),
		enabled:         new(uint32),
		cacheExceptions: pm,
	}
	return c
}

func (c *Cache) ShouldCache(key string) bool {
	if atomic.LoadUint32(c.enabled) == 0 {
		return false
	}

	return !c.cacheExceptions.HasPath(key)
}

func (c *Cache) Put(ctx context.Context, entry *v1.Entry) error {
	if entry != nil && !c.ShouldCache(entry.Key) {
		return c.store.Put(ctx, entry)
	}

	lock := utils.LockForKey(c.locks, entry.Key)
	lock.Lock()
	defer lock.Unlock()

	err := c.store.Put(ctx, entry)
	if err == nil {
		c.lru.Add(entry.Key, entry)
	}
	return err
}

func (c *Cache) SetEnabled(enabled bool) {
	if enabled {
		atomic.StoreUint32(c.enabled, 1)
		return
	}
	atomic.StoreUint32(c.enabled, 0)
}

func (c *Cache) Purge(ctx context.Context) {
	// Lock the world
	for _, lock := range c.locks {
		lock.Lock()
		defer lock.Unlock()
	}

	c.lru.Purge()
}

func (c *Cache) Get(ctx context.Context, key string) (*v1.Entry, error) {
	if !c.ShouldCache(key) {
		return c.store.Get(ctx, key)
	}

	lock := utils.LockForKey(c.locks, key)
	lock.RLock()
	defer lock.RUnlock()

	// Check the LRU first
	if !cacheRefreshFromContext(ctx) {
		if raw, ok := c.lru.Get(key); ok {
			if raw == nil {
				return nil, nil
			}
			return raw.(*v1.Entry), nil
		}
	}

	ent, err := c.store.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	// Cache the result, even if nil
	c.lru.Add(key, ent)

	return ent, nil
}

func (c *Cache) Delete(ctx context.Context, key string) error {
	if !c.ShouldCache(key) {
		return c.store.Delete(ctx, key)
	}

	lock := utils.LockForKey(c.locks, key)
	lock.Lock()
	defer lock.Unlock()

	err := c.store.Delete(ctx, key)
	if err == nil {
		c.lru.Remove(key)
	}
	return err
}

func (c *Cache) List(ctx context.Context, prefix string) ([]string, error) {
	return c.store.List(ctx, prefix)
}
