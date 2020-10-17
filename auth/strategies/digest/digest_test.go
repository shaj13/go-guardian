//nolint: lll
package digest

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/lru"
	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/auth"
)

func TestStartegy(t *testing.T) {
	fn := func(userName string) (string, auth.Info, error) {
		if userName == "error" {
			return "", nil, fmt.Errorf("Error #L 51")
		}
		return "", nil, nil
	}

	table := []struct {
		name        string
		authz       string
		expectedErr bool
	}{
		{
			name:        "it return error when failed to parse header",
			authz:       "Test",
			expectedErr: true,
		},
		{
			name:  "it authinticate user",
			authz: `Digest username="a", realm="t", nonce="1", uri="/", cnonce="1=", nc=00000001, qop=auth, response="22cf307b29e6318dafba1fc1d564fc12", opaque="1", algorithm="md5"`,
		},
		{
			name:        "it return error when username is invalid",
			authz:       `Digest username="error"`,
			expectedErr: true,
		},
		{
			name:        "it return error when response does not match server hash",
			authz:       `Digest username="a" response="hash"`,
			expectedErr: true,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			strategy := testDigest(fn)
			r, _ := http.NewRequest("GEt", "/", nil)
			r.Header.Set("Authorization", tt.authz)
			_, err := strategy.Authenticate(r.Context(), r)
			assert.Equal(t, tt.expectedErr, err != nil, err)
		})
	}
}

func BenchmarkStrategy(b *testing.B) {
	authz := `Digest username="a", realm="t", nonce="1", uri="/", cnonce="1=", nc=00000001, qop=auth, response="22cf307b29e6318dafba1fc1d564fc12", opaque="1", algorithm="md5"`
	fn := func(userName string) (string, auth.Info, error) {
		return "", nil, nil
	}

	strategy := testDigest(fn)

	r, _ := http.NewRequest("GEt", "/", nil)
	r.Header.Set("Authorization", authz)

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

func testDigest(fn FetchUser) auth.Strategy {
	opaque := SetOpaque("1")
	realm := SetRealm("t")
	cache := libcache.LRU.New(0)
	cache.Store("1", nil)
	return New(fn, cache, opaque, realm)
}
