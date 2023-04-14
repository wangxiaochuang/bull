package pathmanager

import (
	"strings"
	"sync"

	iradix "github.com/zilicorp/bull/pkg/radix"
)

type PathManager struct {
	l     sync.RWMutex
	paths *iradix.Tree
}

func New() *PathManager {
	return &PathManager{
		paths: iradix.New(),
	}
}

func (p *PathManager) AddPaths(paths []string) {
	p.l.Lock()
	defer p.l.Unlock()

	txn := p.paths.Txn()
	for _, prefix := range paths {
		if len(prefix) == 0 {
			continue
		}

		var exception bool
		if strings.HasPrefix(prefix, "!") {
			prefix = strings.TrimPrefix(prefix, "!")
			exception = true
		}
		txn.Insert([]byte(strings.TrimSuffix(prefix, "*")), exception)
	}
	p.paths = txn.Commit()
}

func (p *PathManager) HasPath(path string) bool {
	p.l.RLock()
	defer p.l.RUnlock()

	if _, exceptionRaw, ok := p.paths.Root().LongestPrefix([]byte(path)); ok {
		var exception bool
		if exceptionRaw != nil {
			exception = exceptionRaw.(bool)
		}
		return !exception
	}
	return false
}
