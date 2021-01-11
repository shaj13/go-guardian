package jwt

import (
	"time"

	"github.com/dgrijalva/jwt-go/v4"

	"github.com/shaj13/go-guardian/v2/auth"
)

type claims struct {
	UserInfo   auth.Info        `json:"info"`
	Issuer     string           `json:"iss"`
	Subject    string           `json:"sub"`
	Audience   jwt.ClaimStrings `json:"aud"`
	Expiration time.Time        `json:"exp"`
	NotBefore  time.Time        `json:"nbf"`
	IssuedAt   time.Time        `json:"iat"`
}

// nolint:govet
func (c claims) Valid(v *jwt.ValidationHelper) error {
	if err := v.ValidateAudience(c.Audience); err != nil {
		return err
	}

	if err := v.ValidateIssuer(c.Issuer); err != nil {
		return err
	}

	if err := v.ValidateNotBefore(&jwt.Time{c.NotBefore}); err != nil {
		return err
	}

	return v.ValidateExpiresAt(&jwt.Time{c.Expiration})
}
