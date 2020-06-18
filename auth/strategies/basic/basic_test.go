package basic

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/auth"
)

//nolint:goconst
func Test(t *testing.T) {
	auth := func(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error) {
		if userName == "test" && password == "test" {
			return auth.NewDefaultUser("test", "10", nil, nil), nil
		}

		return nil, fmt.Errorf("Invalid credentials")
	}

	table := []struct {
		name           string
		setCredentials func(r *http.Request)
		expectedErr    bool
	}{
		{
			name:           "it return user info when request authenticated",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("test", "test") },
			expectedErr:    false,
		},
		{
			name:           "it return error when request has invalid credentials",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("unknown", "unknown") },
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
			info, err := AuthenticateFunc(auth).Authenticate(r.Context(), r)

			if tt.expectedErr && err == nil {
				t.Errorf("%s: Expected error, got none", tt.name)
				return
			}

			if !tt.expectedErr && info == nil {
				t.Errorf("%s: Expected info object, got nil: %v", tt.name, err)
				return
			}
		})
	}
}

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
			name:           "it return error when cache return error on load",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("error", "test") },
			expectedErr:    true,
		},
		{
			name:           "it return error when cache return error on store",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("store-error", "test") },
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

			c := newMockCache()
			c.cache["predefined"] = "invalid-type"
			c.cache["predefined2"] = auth.NewDefaultUser(
				"predefined2",
				"10",
				nil,
				map[string][]string{
					ExtensionKey: {"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
				},
			)
			c.cache["predefined3"] = auth.NewDefaultUser("predefined3", "10", nil, nil)

			info, err := New(authFunc, c).Authenticate(r.Context(), r)

			assert.Equal(t, tt.expectedErr, err != nil, "%s: Got Unexpected error %v", tt.name, err)
			assert.Equal(t, !tt.expectedErr, info != nil, "%s: Expected info object, got nil", tt.name)
		})
	}
}

func BenchmarkCachedBasic(b *testing.B) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth("test", "test")

	cache := newMockCache()

	strategy := New(exampleAuthFunc, cache)

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

func BenchmarkBasic(b *testing.B) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth("test", "test")

	strategy := AuthenticateFunc(exampleAuthFunc)

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

type mockCache struct {
	cache map[string]interface{}
	mu    *sync.Mutex
}

func (m mockCache) Load(key string, _ *http.Request) (interface{}, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if key == "error" {
		return nil, false, fmt.Errorf("Load Error")
	}
	v, ok := m.cache[key]
	return v, ok, nil
}

func (m mockCache) Store(key string, value interface{}, _ *http.Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if key == "store-error" {
		return fmt.Errorf("Store Error")
	}
	m.cache[key] = value
	return nil
}

func (m mockCache) Delete(key string, _ *http.Request) error {
	return nil
}

func newMockCache() mockCache {
	return mockCache{
		cache: make(map[string]interface{}),
		mu:    new(sync.Mutex),
	}
}
