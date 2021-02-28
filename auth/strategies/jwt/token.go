package jwt

import (
	"fmt"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/internal/jwt"
)

const (
	// EdDSA signature algorithm.
	EdDSA = "EdDSA"
	// HS256 signature algorithm -- HMAC using SHA-256.
	HS256 = "HS256"
	// HS384 signature algorithm -- HMAC using SHA-384.
	HS384 = "HS384"
	// HS512 signature algorithm -- HMAC using SHA-512.
	HS512 = "HS512"
	// RS256 signature algorithm -- RSASSA-PKCS-v1.5 using SHA-256.
	RS256 = "RS256"
	// RS384 signature algorithm -- RSASSA-PKCS-v1.5 using SHA-384.
	RS384 = "RS384"
	// RS512 signature algorithm -- RSASSA-PKCS-v1.5 using SHA-512.
	RS512 = "RS512"
	// ES256 signature algorithm -- ECDSA using P-256 and SHA-256.
	ES256 = "ES256"
	// ES384 signature algorithm -- ECDSA using P-384 and SHA-384.
	ES384 = "ES384"
	// ES512 signature algorithm -- ECDSA using P-521 and SHA-512.
	ES512 = "ES512"
	// PS256 signature algorithm -- RSASSA-PSS using SHA256 and MGF1-SHA256.
	PS256 = "PS256"
	// PS384 signature algorithm -- RSASSA-PSS using SHA384 and MGF1-SHA384.
	PS384 = "PS384"
	// PS512 signature algorithm -- RSASSA-PSS using SHA512 and MGF1-SHA512.
	PS512 = "PS512"
)

var (
	// ErrMissingKID is returned by Authenticate Strategy method,
	// when failed to retrieve kid from token header.
	ErrMissingKID = jwt.ErrMissingKID

	// ErrInvalidAlg is returned by Authenticate Strategy method,
	// when jwt token alg header does not match key algorithm.
	ErrInvalidAlg = jwt.ErrInvalidAlg
)

// IssueAccessToken issue jwt access token for the provided user info.
func IssueAccessToken(info auth.Info, s SecretsKeeper, opts ...auth.Option) (string, error) {
	return newAccessToken(s, opts...).issue(info)
}

type accessToken struct {
	keeper SecretsKeeper
	dur    time.Duration
	aud    string
	iss    string
	scp    []string
}

func (at accessToken) issue(info auth.Info) (string, error) {
	now := time.Now().UTC().Add(-claims.DefaultLeeway)
	exp := now.Add(at.dur)

	c := claims.Standard{
		Subject:   info.GetID(),
		Issuer:    at.iss,
		Audience:  claims.StringOrList{at.aud},
		ExpiresAt: (*claims.Time)(&exp),
		IssuedAt:  (*claims.Time)(&now),
		NotBefore: (*claims.Time)(&now),
		Scope:     at.scp,
	}

	str, err := jwt.IssueToken(at.keeper, c, info)
	if err != nil {
		return "", fmt.Errorf("strategies/jwt: %w", err)
	}

	return str, nil
}

func (at accessToken) parse(tstr string) (claims.Standard, auth.Info, error) {
	fail := func(err error) (claims.Standard, auth.Info, error) {
		return claims.Standard{}, nil, fmt.Errorf("strategies/jwt: %w", err)
	}

	info := auth.NewUserInfo("", "", nil, make(auth.Extensions))
	c := claims.Standard{}
	opts := claims.VerifyOptions{
		Audience: claims.StringOrList{at.aud},
		Issuer:   at.iss,
		Time: func() (t time.Time) {
			return time.Now().UTC().Add(-claims.DefaultLeeway)
		},
	}

	if err := jwt.ParseToken(at.keeper, tstr, &c, info); err != nil {
		return fail(err)
	}

	if err := c.Verify(opts); err != nil {
		return fail(err)
	}

	return c, info, nil
}

func newAccessToken(s SecretsKeeper, opts ...auth.Option) *accessToken {
	t := new(accessToken)
	t.keeper = s
	t.aud = ""
	t.iss = ""
	t.dur = time.Minute * 5
	for _, opt := range opts {
		opt.Apply(t)
	}
	return t
}
