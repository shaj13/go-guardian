//nolint: lll
package digest

import (
	"crypto/md5"
	"fmt"
	"hash"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/auth"
)

func TestWWWAuthenticate(t *testing.T) {
	s := &Strategy{
		Algorithm: "md5",
		Realm:     "test",
	}

	h := make(http.Header)

	s.WWWAuthenticate(h)
	str := h.Get("WWW-Authenticate")
	assert.Contains(t, str, `qop="auth"`)
	assert.Contains(t, str, "Digest")
	assert.Contains(t, str, "algorithm=md5")
	assert.Contains(t, str, "opaque=")
	assert.Contains(t, str, "nonce=")
	assert.Contains(t, str, `realm="test"`)
}

func TestChallenge(t *testing.T) {
	s := &Strategy{
		Algorithm: "md5",
	}

	str := s.Challenge("test2")

	assert.Contains(t, str, `qop="auth"`)
	assert.Contains(t, str, "Digest")
	assert.Contains(t, str, "algorithm=md5")
	assert.Contains(t, str, "opaque=")
	assert.Contains(t, str, "nonce=")
	assert.Contains(t, str, `realm="test2"`)
}

func TestStartegy(t *testing.T) {
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
			authz: `Digest username="a", realm="t", nonce="1", uri="/", cnonce="1=", nc=00000001, qop=auth, response="22cf307b29e6318dafba1fc1d564fc12", opaque="1"`,
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
			s := Strategy{
				Algorithm: "md5",
				Realm:     "test",
				FetchUser: func(userName string) (string, auth.Info, error) {
					if userName == "error" {
						return "", nil, fmt.Errorf("Error #L 51")
					}
					return "", nil, nil
				},
				Hash: func(algo string) hash.Hash {
					return md5.New()
				},
			}

			r, _ := http.NewRequest("GEt", "/", nil)
			r.Header.Set("Authorization", tt.authz)
			_, err := s.Authenticate(r.Context(), r)
			assert.Equal(t, tt.expectedErr, err != nil)
		})
	}
}

func BenchmarkStrategy(b *testing.B) {
	authz := `Digest username="a", realm="t", nonce="1", uri="/", cnonce="1=", nc=00000001, qop=auth, response="22cf307b29e6318dafba1fc1d564fc12", opaque="1"`
	s := Strategy{
		Algorithm: "md5",
		Realm:     "test",
		FetchUser: func(userName string) (string, auth.Info, error) {
			return "", nil, nil
		},
		Hash: func(algo string) hash.Hash {
			return md5.New()
		},
	}

	r, _ := http.NewRequest("GEt", "/", nil)
	r.Header.Set("Authorization", authz)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := s.Authenticate(r.Context(), r)
			if err != nil {
				b.Error(err)
			}
		}
	})
}
