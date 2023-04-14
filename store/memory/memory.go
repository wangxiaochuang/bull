package memory

import (
	"context"
	"strings"

	"github.com/armon/go-radix"
	v1 "github.com/zilicorp/bull/pkg/api/core/v1"
	"github.com/zilicorp/bull/store"
)

var _ store.Store = (*memoryStore)(nil)

type memoryStore struct {
	root *radix.Tree
}

func NewMemoryStore() (store.Store, error) {
	return &memoryStore{
		root: radix.New(),
	}, nil
}

func (s *memoryStore) Put(ctx context.Context, entry *v1.Entry) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.root.Insert(entry.Key, entry.Value)
	return nil
}

func (s *memoryStore) Get(ctx context.Context, key string) (*v1.Entry, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if raw, ok := s.root.Get(key); ok {
		return &v1.Entry{
			Key:   key,
			Value: raw.([]byte),
		}, nil
	}
	return nil, nil
}

func (s *memoryStore) Delete(ctx context.Context, key string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.root.Delete(key)
	return nil
}

func (s *memoryStore) List(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	seen := make(map[string]interface{})
	walkFn := func(s string, v interface{}) bool {
		trimmed := strings.TrimPrefix(s, prefix)
		sep := strings.Index(trimmed, "/")
		if sep == -1 {
			out = append(out, trimmed)
		} else {
			trimmed = trimmed[:sep+1]
			if _, ok := seen[trimmed]; !ok {
				out = append(out, trimmed)
				seen[trimmed] = struct{}{}
			}
		}
		return false
	}
	s.root.WalkPrefix(prefix, walkFn)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return out, nil
}
