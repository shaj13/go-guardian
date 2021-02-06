package jwt

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestJWKSKID(t *testing.T) {
	jwks := new(jwks)
	assert.Empty(t, jwks.KID())
}

func TestJWKSGet(t *testing.T) {
	table := []struct {
		kid         string
		expectedAlg string
		expectedErr bool
		expectedKey bool
	}{
		{
			kid:         "fdb40e2f9353c58add648b63634e5bbf63e4f502",
			expectedAlg: "RS256",
			expectedKey: true,
		},
		{
			kid:         "fed80fec56db99233d4b4f60fbafdbaeb9186c73",
			expectedAlg: "RS256",
			expectedKey: true,
		},
		{
			kid:         "fed80fec56db99233d4b4f60fbafdbaeb9186192",
			expectedErr: true,
		},
	}

	srv := mockAuthzServer(t, "jwks.json", nil)
	defer srv.Close()
	jwks := newJWKS(srv.URL)

	for _, tt := range table {
		key, alg, err := jwks.Get(tt.kid)
		assert.Equal(t, tt.expectedErr, err != nil)
		assert.Equal(t, tt.expectedKey, key != nil)
		assert.Equal(t, tt.expectedAlg, alg)
	}
}

func TestJWKSsetExpiresAt(t *testing.T) {
	table := []struct {
		name     string
		header   string
		expected time.Time
		interval time.Duration
	}{
		{
			name:     "it set time from interval when no max age",
			expected: time.Now().Add(time.Minute).UTC(),
			interval: time.Minute,
		},
		{
			name:     "it set time from interval when max age invalid",
			header:   "public, max-age=invalid",
			expected: time.Now().Add(time.Minute).UTC(),
			interval: time.Minute,
		},
		{
			name:     "it set time from interval when max age invalid",
			header:   "public, max-age=23180",
			expected: time.Now().Add(time.Duration(23180) * time.Second).UTC(),
			interval: time.Minute,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			jwks := &jwks{interval: tt.interval}
			h := http.Header{}
			h.Set(cacheControl, tt.header)
			jwks.setExpiresAt(h)
			assert.WithinDuration(t, tt.expected, jwks.expiresAt, time.Second)
		})
	}
}

func BenchmarkJWKSLoad(b *testing.B) {
	counter := 0
	srv := mockAuthzServer(b, "jwks.json", &counter)
	defer srv.Close()
	jwks := newJWKS(srv.URL)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _ = jwks.Get("")
		}
	})

	if counter != 1 {
		b.Error("the load method has not been Invoked or too many  invocation")
	}
}

func mockAuthzServer(tb testing.TB, file string, counter *int) *httptest.Server {
	body, err := ioutil.ReadFile("./testdata/" + file)

	if err != nil {
		tb.Fatalf("Failed to read testdata file Err: %s", err)
	}

	h := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(body)
		if counter != nil {
			*counter++
		}
	}

	return httptest.NewServer(http.HandlerFunc(h))
}
