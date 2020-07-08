package store

import (
	"context"
	"encoding/gob"
	"fmt"
	"os"
	"sync"
	"time"

	// "net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileSystemStore(t *testing.T) {
	table := []struct {
		name        string
		expectedErr bool
		key         string
		value       interface{}
		ttl         time.Duration
	}{
		{
			name:        "it return error when failed to encode value",
			expectedErr: true,
			key:         "error",
			value:       &struct{ int }{1},
		},
		{
			name:        "it return nil error and store data in filesystem",
			expectedErr: false,
			key:         "key",
			value:       "value",
		},
		{
			name:        "it push record to queue when ttl > 0",
			expectedErr: false,
			key:         "queue",
			value:       "value",
			ttl:         time.Second,
		},
	}

	for i, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			path := fmt.Sprintf("/tmp/test/%v", i)
			os.MkdirAll(path, os.ModePerm)
			defer os.RemoveAll(path)

			f := &FileSystem{
				path: path,
				MU:   &sync.RWMutex{},
				queue: &queue{
					notify: make(chan struct{}, 1),
					mu:     &sync.Mutex{},
				},
				TTL: tt.ttl,
			}

			err := f.Store(tt.key, tt.value, nil)

			if tt.expectedErr {
				assert.True(t, err != nil)
				return
			}

			if tt.ttl > 0 {
				r := f.queue.next()
				assert.Equal(t, nil, r.Value)
				assert.Equal(t, tt.key, r.Key)
			}

			_, err = os.Stat(f.fileName(tt.key))
			assert.NoError(t, err)

		})
	}
}

func TestFileSystemLoad(t *testing.T) {
	table := []struct {
		name        string
		expectedErr bool
		key         string
		value       interface{}
		found       bool
	}{
		{
			name:        "it return error when failed to decode",
			expectedErr: true,
			key:         "error",
			value:       nil,
			found:       true,
		},
		{
			name:        "it return false and nil error when record does not exist",
			expectedErr: false,
			key:         "notfound",
			value:       nil,
			found:       false,
		},
		{
			name:        "it return value",
			expectedErr: false,
			key:         "key",
			value:       "value",
			found:       true,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cacnel := context.WithCancel(context.Background())
			defer cacnel()

			f := NewFileSystem(ctx, 0, "./testdata")
			v, ok, err := f.Load(tt.key, nil)

			assert.Equal(t, tt.expectedErr, err != nil)
			assert.Equal(t, tt.value, v)
			assert.Equal(t, tt.found, ok)

		})
	}
}

func TestFileSystemKeys(t *testing.T) {
	ctx, cacnel := context.WithCancel(context.Background())
	defer cacnel()

	f := NewFileSystem(ctx, 0, "./testdata")
	keys := f.Keys()
	expected := []string{"error", "key", "queue"}

	assert.ElementsMatch(t, keys, expected)
}

func TestFileSystemName(t *testing.T) {
	f := new(FileSystem)
	f.path = "/test"

	got := f.fileName("key")
	expected := "/test/key.cache.gob"

	assert.Equal(t, expected, got)
}

func TestFileSystemDelete(t *testing.T) {
	f := new(FileSystem)
	f.path = "/tmp"
	f.MU = new(sync.RWMutex)

	filename := f.fileName("deletekey")
	os.OpenFile(filename, os.O_RDONLY|os.O_CREATE, 0666)

	err := f.Delete("deletekey", nil)
	assert.NoError(t, err)

	_, err = os.Stat(filename)
	assert.Error(t, err)
}

func BenchmarkFileSystem(b *testing.B) {
	gob.Register(struct{}{})
	cache := NewFileSystem(context.Background(), 0, "/tmp")
	benchmarkCache(b, cache)
}
