package main

import (
	"github.com/zilicorp/bull/bull"
	"github.com/zilicorp/bull/store/memory"
)

func main() {
	store, _ := memory.NewMemoryStore()
	coreConfig := &bull.CoreConfig{
		store: store,
	}
	bull.NewCore(coreConfig)
}
