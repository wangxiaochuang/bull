package store

import (
	"context"

	v1 "github.com/zilicorp/bull/api/core/v1"
)

type Store interface {
	Put(ctx context.Context, entry *v1.Entry) error

	Get(ctx context.Context, key string) (*v1.Entry, error)

	Delete(ctx context.Context, key string) error

	List(ctx context.Context, prefix string) ([]string, error)
}
