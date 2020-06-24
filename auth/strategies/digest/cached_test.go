//nolint: lll, goconst
package digest

import (
	"crypto/md5"
	"fmt"
	"hash"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/auth"
)

func TestNewCahced(t *testing.T) {
	table := []struct {
		name        string
		expectedErr bool
		info        interface{}
		key         string
		header      string
	}{
		{
			name:        "it return error when cache load return error",
			expectedErr: true,
			header:      "Digest nonce=error",
			info:        nil,
		},
		{
			name:        "it return error when user authenticate func return error",
			expectedErr: true,
			header:      "Digest nonce=ignore",
			info:        nil,
		},
		{
			name:        "it return error when cache store return error",
			expectedErr: true,
			header:      `Digest username="a", realm="t", nonce="store-error", uri="/", cnonce="1=", nc=00000001, qop=auth, response="14979b5053904998faf57bc72a1d7a56", opaque="1"`,
			info:        nil,
		},
		{
			name:        "it return error when cache return invalid type",
			expectedErr: true,
			info:        "sample-data",
			header:      "Digest nonce=invalid",
			key:         "invalid",
		},
		{
			name:        "it authinticate user",
			expectedErr: false,
			info:        nil,
			header:      `Digest username="a", realm="t", nonce="150", uri="/", cnonce="1=", nc=00000001, qop=auth, response="22b46269226822f5edde5a52985679ad", opaque="1"`,
		},
		{
			name:        "it authinticate user even if nc, uri changed and load it from cache",
			expectedErr: false,
			info: auth.NewDefaultUser(
				"test",
				"1",
				nil,
				map[string][]string{
					extensionKey: {`Digest username="a", realm="t", nonce="150", uri="/abc", cnonce="1=", nc=00000001, qop=auth, response="22b46269226822f5edde5a52985679ad", opaque="1"`},
				},
			),
			key:    "150",
			header: `Digest username="a", realm="t", nonce="150", uri="/", cnonce="1=", nc=00000002, qop=auth, response="22b46269226822f5edde5a52985679ad", opaque="1"`,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			cache := newMockCache()

			s := &CachedStrategy{
				Strategy: &Strategy{
					Algorithm: "md5",
					Realm:     "test",
					FetchUser: func(userName string) (string, auth.Info, error) {
						if userName == "error" {
							return "", nil, fmt.Errorf("Error #L 51")
						}
						return "", auth.NewDefaultUser("test", "1", nil, nil), nil
					},
					Hash: func(algo string) hash.Hash {
						return md5.New()
					},
				},
				Cache: cache,
			}

			r, _ := http.NewRequest("GET", "/", nil)
			r.Header.Set("Authorization", tt.header)

			_ = cache.Store(tt.key, tt.info, r)

			_, err := s.Authenticate(r.Context(), r)

			assert.Equal(t, tt.expectedErr, err != nil)
		})
	}
}

func BenchmarkCached(b *testing.B) {
	count := 0

	authz := `Digest username="a", realm="t", nonce="1", uri="/", cnonce="1=", nc=00000001, qop=auth, response="60bf91821e3499f7b04f3de9ee7e3aa6", opaque="1"`
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", authz)

	strategy := &CachedStrategy{
		Strategy: &Strategy{
			Algorithm: "md5",
			Realm:     "test",
			FetchUser: func(userName string) (string, auth.Info, error) {
				count++
				if count >= 10 {
					b.Fatal("Function fetch user called more than 10 times this should not happens in cached strategy")
				}
				return "", auth.NewDefaultUser("benchmark", "1", nil, nil), nil
			},
			Hash: func(algo string) hash.Hash {
				return md5.New()
			},
		},
		Cache: newMockCache(),
	}

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
	if key == "ignore" {
		return nil
	}

	if strings.Contains(key, "store-error") {
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
