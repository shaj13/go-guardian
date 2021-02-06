package basic

import (
	"context"
	"crypto"
	_ "crypto/sha256"
	"fmt"
	"net/http"
	"testing"

	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/lru"
	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/auth"
)

//nolint:goconst
func TestNewCached(t *testing.T) {
	authFunc := func(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error) {
		if userName == "auth-error" {
			return nil, fmt.Errorf("Invalid credentials")
		}

		return auth.NewDefaultUser("test", "10", nil, nil), nil
	}

	table := []struct {
		name           string
		setCredentials func(r *http.Request)
		expectedErr    bool
	}{
		{
			name:           "it return user from cache",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("predefined2", "test") },
			expectedErr:    false,
		},
		{
			name:           "it re-authenticate user when hash missing",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("predefined3", "test") },
			expectedErr:    false,
		},
		{
			name:           "it return error when cache hold invalid user info",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("predefined", "test") },
			expectedErr:    true,
		},
		{
			name:           "it return user info when request authenticated",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("test", "test") },
			expectedErr:    false,
		},
		{
			name:           "it return error when request has invalid credentials",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("auth-error", "unknown") },
			expectedErr:    true,
		},
		{
			name:           "it return error when request missing basic auth params",
			setCredentials: func(r *http.Request) { /* no op */ },
			expectedErr:    true,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			tt.setCredentials(r)

			cache := libcache.LRU.New(0)
			cache.Store("predefined", "invalid-type")
			cache.Store("predefined2", auth.NewDefaultUser(
				"predefined2",
				"10",
				nil,
				map[string][]string{
					ExtensionKey: {"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
				},
			))
			cache.Store("predefined3", auth.NewDefaultUser("predefined3", "10", nil, nil))

			opt := SetHash(crypto.SHA256)
			info, err := NewCached(authFunc, cache, opt).Authenticate(r.Context(), r)

			assert.Equal(t, tt.expectedErr, err != nil, "%s: Got Unexpected error %v", tt.name, err)
			assert.Equal(t, !tt.expectedErr, info != nil, "%s: Expected info object, got nil", tt.name)
		})
	}
}

func TestCachedUserNameHash(t *testing.T) {
	count := 0
	user := "test"
	cache := libcache.LRU.New(0)
	opt := SetUserNameHash(crypto.SHA256, []byte("key"))
	fn := func(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error) {
		count++
		return auth.NewDefaultUser(user, "10", nil, nil), nil
	}
	basic := NewCached(fn, cache, opt)
	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth(user, user)
	for i := 0; i < 10; i++ {
		info, err := basic.Authenticate(r.Context(), r)
		assert.NoError(t, err)
		assert.Equal(t, info.GetUserName(), user)
		assert.False(t, cache.Contains(user))
	}
	assert.Equal(t, 1, cache.Len())
	assert.Equal(t, 1, count)
}

func BenchmarkCachedBasic(b *testing.B) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth("test", "test")

	cache := libcache.LRU.New(1)

	strategy := NewCached(exampleAuthFunc, cache)

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
