package bull

import (
	"fmt"

	"github.com/zilicorp/bull/barrier"
	"github.com/zilicorp/bull/store"
	"github.com/zilicorp/bull/store/cache"
)

type CoreConfig struct {
	store store.Store
}

type Core struct {
	store           store.Store
	underlyingStore store.Store
	sealUnwrapper   store.Store

	barrier barrier.SecurityBarrier

	storeCache store.ToggleablePurgemonster
}

func coreInit(c *Core, conf *CoreConfig) error {
	c.store = cache.NewCache(conf.store, 0)
	c.storeCache = c.store.(store.ToggleablePurgemonster)
	return nil
}

func CreateCore(conf *CoreConfig) (*Core, error) {
	c := &Core{
		store: conf.store,
	}

	return c, nil
}

func NewCore(conf *CoreConfig) (*Core, error) {
	var err error
	c, err := CreateCore(conf)
	if err != nil {
		return nil, err
	}

	if err = coreInit(c, conf); err != nil {
		return nil, err
	}

	c.barrier, err = barrier.NewAESGCMBarrier(c.store)
	if err != nil {
		return nil, fmt.Errorf("barrier setup failed: %w", err)
	}

	return nil, nil
}
