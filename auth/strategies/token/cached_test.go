package token

import (
	"context"
	"net/http"
	"testing"

	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/lru"
	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/auth"
)

func TestNewCahced(t *testing.T) {
	table := []struct {
		name        string
		panic       bool
		expectedErr bool
		authFunc    AuthenticateFunc
		info        interface{}
		token       string
	}{
		{
			name:        "it return error when user authenticate func return error",
			expectedErr: true,
			authFunc:    NoOpAuthenticate,
			panic:       false,
			info:        nil,
		},
		{
			name:        "it return error when cache return invalid type",
			expectedErr: true,
			authFunc:    func(_ context.Context, _ *http.Request, _ string) (auth.Info, error) { return nil, nil },
			panic:       false,
			info:        "sample-data",
			token:       "valid",
		},
		{
			name:        "it return user when token cached",
			expectedErr: false,
			authFunc:    NoOpAuthenticate,
			panic:       false,
			info:        auth.NewDefaultUser("1", "1", nil, nil),
			token:       "valid-user",
		},
		{
			name:        "it panic when Authenticate func nil",
			expectedErr: false,
			panic:       true,
			info:        nil,
		},
		{
			name:        "it panic when Cache nil",
			expectedErr: false,
			authFunc:    NoOpAuthenticate,
			panic:       true,
			info:        nil,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			if tt.panic {
				assert.Panics(t, func() {
					New(tt.authFunc, nil)
				})
				return
			}

			cache := libcache.LRU.New(0)
			strategy := New(tt.authFunc, cache)
			r, _ := http.NewRequest("GET", "/", nil)
			r.Header.Set("Authorization", "Bearer "+tt.token)
			cache.Store(tt.token, tt.info)
			info, err := strategy.Authenticate(r.Context(), r)
			if tt.expectedErr {
				assert.Error(t, err)
				return
			}
			assert.Equal(t, tt.info, info)
		})
	}
}

func TestCahcedTokenAppend(t *testing.T) {
	cache := libcache.LRU.New(0)
	strategy := &cachedToken{cache: cache}
	info := auth.NewDefaultUser("1", "2", nil, nil)
	strategy.Append("test-append", info)
	cachedInfo, ok := cache.Load("test-append")
	assert.True(t, ok)
	assert.Equal(t, info, cachedInfo)
}

func BenchmarkCachedToken(b *testing.B) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer token")

	cache := libcache.LRU.New(0)
	cache.Store("token", auth.NewDefaultUser("benchmark", "1", nil, nil))

	strategy := New(NoOpAuthenticate, cache)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := strategy.Authenticate(r.Context(), r)
			if err != nil {
				b.Error(err)
			}
		}
	})
}
