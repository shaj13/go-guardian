package jwt

import (
	"time"

	"github.com/dgrijalva/jwt-go/v4"

	"github.com/shaj13/go-guardian/v2/auth"
)

const headerKID = "kid"

// IssueAccessToken issue jwt access token for the provided user info.
func IssueAccessToken(info auth.Info, s SecretsKeeper, opts ...auth.Option) (string, error) {
	return newAccessToken(s, opts...).issue(info)
}

type accessToken struct {
	s   SecretsKeeper
	d   time.Duration
	aud jwt.ClaimStrings
	iss string
}

func (at accessToken) issue(info auth.Info) (string, error) {
	kid := at.s.KID()
	secret, method, err := at.s.Get(kid)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	exp := now.Add(at.d)

	c := claims{
		UserInfo:   info,
		Subject:    info.GetUserName(),
		Issuer:     at.iss,
		Audience:   at.aud,
		Expiration: exp,
		NotBefore:  now,
		IssuedAt:   now,
	}

	jt := jwt.NewWithClaims(method, c)
	jt.Header[headerKID] = kid

	return jt.SignedString(secret)
}

func (at accessToken) parse(tstr string) (*claims, error) {
	c := &claims{
		UserInfo: auth.NewUserInfo("", "", nil, nil),
	}

	keyFunc := func(jt *jwt.Token) (interface{}, error) {
		kid := jt.Header[headerKID].(string)
		secret, _, err := at.s.Get(kid)
		return secret, err
	}

	aud := jwt.WithAudience(at.aud[0])
	iss := jwt.WithIssuer(at.iss)

	_, err := jwt.ParseWithClaims(tstr, c, keyFunc, aud, iss)
	return c, err
}

func newAccessToken(s SecretsKeeper, opts ...auth.Option) *accessToken {
	t := new(accessToken)
	t.s = s
	t.aud = jwt.ClaimStrings{""}
	t.iss = "go-guardian"
	t.d = time.Minute * 5
	for _, opt := range opts {
		opt.Apply(t)
	}
	return t
}
