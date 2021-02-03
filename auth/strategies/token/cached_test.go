package token

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/lru"
	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/internal"
)

func TestNewCahced(t *testing.T) {
	table := []struct {
		name        string
		expectedErr bool
		authFunc    AuthenticateFunc
		info        interface{}
		token       string
	}{
		{
			name:        "it return error when user authenticate func return error",
			expectedErr: true,
			authFunc:    NoOpAuthenticate,
			info:        nil,
		},
		{
			name:        "it return error when cache return invalid type",
			expectedErr: true,
			authFunc: func(_ context.Context, _ *http.Request, _ string) (auth.Info, time.Time, error) {
				return nil, time.Time{}, nil
			},
			info:  "sample-data",
			token: "valid",
		},
		{
			name:        "it return user when token cached",
			expectedErr: false,
			authFunc:    NoOpAuthenticate,
			info:        auth.NewDefaultUser("1", "1", nil, nil),
			token:       "valid-user",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
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
	strategy := &cachedToken{
		cache: cache,
		h:     internal.PlainTextHasher{},
	}
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
