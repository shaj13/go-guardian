package jwt

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/stretchr/testify/assert"
)

func TestClaimsValid(t *testing.T) {
	table := []struct {
		name      string
		c         claims
		opt       jwt.ParserOption
		expectErr bool
	}{
		{
			name: "it return nil when claims valid",
			c: claims{
				Expiration: time.Now().Add(time.Hour),
			},
			opt: jwt.WithoutClaimsValidation(),
		},
		{
			name:      "it return error when claims expired",
			expectErr: true,
			c:         claims{},
			opt:       jwt.WithoutClaimsValidation(),
		},
		{
			name:      "it return error when token not valid nbf",
			expectErr: true,
			c: claims{
				NotBefore: time.Now().Add(time.Hour),
			},
			opt: jwt.WithoutClaimsValidation(),
		},
		{
			name:      "it return error when token not valid aud",
			expectErr: true,
			c: claims{
				Audience: jwt.ClaimStrings{"test"},
			},
			opt: jwt.WithAudience("#test#"),
		},
		{
			name:      "it return error when token not valid iss",
			expectErr: true,
			c: claims{
				Issuer: "test",
			},
			opt: jwt.WithIssuer("#test#"),
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			vh := jwt.NewValidationHelper(tt.opt)
			err := tt.c.Valid(vh)
			assert.Equal(t, tt.expectErr, err != nil)
		})
	}
}
