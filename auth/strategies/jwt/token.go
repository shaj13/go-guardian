package jwt

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go/v4"

	"github.com/shaj13/go-guardian/v2/auth"
)

const headerKID = "kid"

// ErrMissingKID is returned by Authenticate Strategy method,
// when failed to retrieve kid from token header.
var ErrMissingKID = errors.New("strategies/jwt: Token missing " + headerKID + "header")

// IssueAccessToken issue jwt access token for the provided user info.
func IssueAccessToken(info auth.Info, s SecretsKeeper, opts ...auth.Option) (string, error) {
	return newAccessToken(s, opts...).issue(info)
}

type claims struct {
	UserInfo auth.Info `json:"info"`
	jwt.StandardClaims
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
		UserInfo: info,
		StandardClaims: jwt.StandardClaims{
			Subject:   info.GetUserName(),
			Issuer:    at.iss,
			Audience:  at.aud,
			ExpiresAt: jwt.At(exp),
			IssuedAt:  jwt.At(now),
			NotBefore: jwt.At(now),
		},
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
		v, ok := jt.Header[headerKID]
		if !ok {
			return nil, ErrMissingKID
		}

		kid, ok := v.(string)
		if !ok {
			return nil, auth.NewTypeError("strategies/jwt: kid", "str", v)
		}

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
