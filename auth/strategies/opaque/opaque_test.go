package opaque

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/lru"
	"github.com/stretchr/testify/require"

	"github.com/shaj13/go-guardian/v2/auth"
)

func TestEverything(t *testing.T) {
	k := StaticSecret([]byte("test"))
	s := &testStore{}
	st := New(libcache.LRU.New(0), s, k)
	info := auth.NewDefaultUser("test", "test_id", nil, nil)

	token, err := IssueToken(context.TODO(), info, s, k)
	require.NoError(t, err)

	r, err := http.NewRequest("", "", nil)
	require.NoError(t, err)

	r.Header.Set("Authorization", "Bearer "+token)
	got, err := st.Authenticate(r.Context(), r)
	require.NoError(t, err)
	require.Equal(t, info, got)

	r.Header.Set("Authorization", "Bearer token")
	got, err = st.Authenticate(r.Context(), r)
	require.Error(t, err)
	require.Nil(t, got)
}

func TestIssue(t *testing.T) {
	tests := []struct {
		k        *testSecretsKeeper
		s        *testStore
		contains string
	}{
		{
			k:        &testSecretsKeeper{},
			contains: "no key to sign token",
		},
		{
			k: &testSecretsKeeper{
				keys: [][]byte{{}},
			},
			s:        &testStore{err: io.ErrShortWrite},
			contains: io.ErrShortWrite.Error(),
		},
		{
			k: &testSecretsKeeper{
				keys: [][]byte{{}},
			},
			s: &testStore{},
		},
	}

	for _, tt := range tests {
		o := newOpaque(tt.s, tt.k)
		_, err := o.issue(context.TODO(), nil)

		if len(tt.contains) > 0 {
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.contains)
			continue
		}

		require.NoError(t, err)
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		k        *testSecretsKeeper
		s        *testStore
		token    string
		contains string
	}{
		{
			token:    "shorttoken",
			contains: "token is too short",
		},
		{
			token:    "00uWYLxs_S-edZagjV_ZlSs0HeM96CxktAd49kVu-_NBWYMfgBboAsg7dPp4tLiXx_N965lcVR8",
			contains: "invalid token prefix",
		},
		{
			token:    "s.############################invalid_token######################################",
			contains: "at input byte 0",
		},
		{
			token:    "s.00uWYLxs_S-edZagjV_ZlSs0HeM96CxktAd49kVu-_NBWYMfgBboAsg7dPp4tLiXx_N965lcVR8",
			k:        &testSecretsKeeper{},
			contains: "no key to sign token",
		},
		{
			token: "s.10uWYLxs_S-edZagjV_ZlSs0HeM96CxktAd49kVu-_NBWYMfgBboAsg7dPp4tLiXx_N965lcVR8",
			k: &testSecretsKeeper{
				keys: [][]byte{{}},
			},
			s:        &testStore{err: io.ErrShortWrite},
			contains: "invalid token signature",
		},
		{
			token: "s._0uWYLxs_S-edZagjV_ZlSs0HeM96CxktAd49kVu-_NBWYMfgBboAsg7dPp4tLiXx_N965lcVR8",
			k: &testSecretsKeeper{
				keys: [][]byte{{}},
			},
			s:        &testStore{err: io.ErrShortWrite},
			contains: io.ErrShortWrite.Error(),
		},
		{
			token: "s._0uWYLxs_S-edZagjV_ZlSs0HeM96CxktAd49kVu-_NBWYMfgBboAsg7dPp4tLiXx_N965lcVR8",
			k: &testSecretsKeeper{
				keys: [][]byte{{}},
			},
			s:        &testStore{},
			contains: "token is expired",
		},
		{
			token: "s._0uWYLxs_S-edZagjV_ZlSs0HeM96CxktAd49kVu-_NBWYMfgBboAsg7dPp4tLiXx_N965lcVR8",
			k: &testSecretsKeeper{
				keys: [][]byte{{}},
			},
			s: &testStore{
				t: Token{
					Lifespan: time.Now().Add(time.Hour),
				},
			},
		},
	}
	for _, tt := range tests {
		o := newOpaque(tt.s, tt.k)
		_, _, err := o.parse(context.TODO(), nil, tt.token)

		if len(tt.contains) > 0 {
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.contains)
			continue
		}

		require.NoError(t, err)
	}
}

type testSecretsKeeper struct {
	keys [][]byte
}

func (s *testSecretsKeeper) Keys() ([][]byte, error) {
	return s.keys, nil
}

type testStore struct {
	err error
	t   Token
}

func (s *testStore) Store(ctx context.Context, t Token) error {
	s.t = t
	return s.err
}

func (s *testStore) Lookup(ctx context.Context, sig string) (Token, error) {
	return s.t, s.err
}

func (s *testStore) Revoke(ctx context.Context, sig string) error {
	return s.err
}
