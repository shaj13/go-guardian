package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/internal/jwt"
)

func Test(t *testing.T) {
	srv := mockAuthzServer(t, "jwks.json", nil)
	defer srv.Close()
	s := newStrategy(srv.URL)

	table := []struct {
		name        string
		token       string
		expectedErr string
	}{
		{
			name:        "it return's error when failed to parse jwt",
			expectedErr: "format must have three parts",
		},
		{
			name:        "it return's error when token expired",
			token:       generateJWT(t, s.jwks, -time.Hour),
			expectedErr: "claims has expired",
		},
		{
			name:  "it return's user info when token valid",
			token: generateJWT(t, s.jwks, time.Hour),
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			info, _, err := s.authenticate(context.TODO(), nil, tt.token)
			if len(tt.expectedErr) > 0 {
				assert.Contains(t, err.Error(), tt.expectedErr)
				return
			}
			assert.True(t, info != nil)
		})
	}
}

func generateJWT(tb testing.TB, jwks *jwks, d time.Duration) string {
	j := testJwks{jwks}
	exp := claims.Time(time.Now().Add(d))
	claims := &claims.Standard{
		Subject:   "test",
		ExpiresAt: &exp,
	}
	str, err := jwt.IssueToken(j, claims)
	if err != nil {
		tb.Errorf("Failed to generate test JWT token, Err: %v", err)
	}
	return str
}

type testJwks struct {
	*jwks
}

func (j testJwks) KID() string {
	j.Get("")
	for _, v := range j.keys {
		return v.KeyID
	}
	return ""
}
