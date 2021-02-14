package jwt

import (
	"errors"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/shaj13/go-guardian/v2/auth"
)

const headerKID = "kid"

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
	// ES384 signature algorithm --  ECDSA using P-384 and SHA-384.
	ES384 = "ES384"
	// ES512 signature algorithm --  ECDSA using P-521 and SHA-512.
	ES512 = "ES512"
	// PS256 signature algorithm --  RSASSA-PSS using SHA256 and MGF1-SHA256.
	PS256 = "PS256"
	// PS384 signature algorithm -- RSASSA-PSS using SHA384 and MGF1-SHA384.
	PS384 = "PS384"
	// PS512 signature algorithm -- RSASSA-PSS using SHA512 and MGF1-SHA512.
	PS512 = "PS512"
)

var (
	// ErrMissingKID is returned by Authenticate Strategy method,
	// when failed to retrieve kid from token header.
	ErrMissingKID = errors.New("strategies/jwt: Token missing " + headerKID + " header")

	// ErrInvalidAlg is returned by Authenticate Strategy method,
	// when jwt token alg header does not match key algorithm.
	ErrInvalidAlg = errors.New("strategies/jwt: Invalid signing algorithm, token alg header does not match key algorithm")
)

// IssueAccessToken issue jwt access token for the provided user info.
func IssueAccessToken(info auth.Info, s SecretsKeeper, opts ...auth.Option) (string, error) {
	return newAccessToken(s, opts...).issue(info)
}

type claims struct {
	UserInfo auth.Info `json:"info"`
	Scopes   []string  `json:"scp"`
	jwt.Claims
}

type accessToken struct {
	keeper SecretsKeeper
	dur    time.Duration
	aud    string
	iss    string
	scp    []string
}

func (at accessToken) issue(info auth.Info) (string, error) {
	kid := at.keeper.KID()
	secret, alg, err := at.keeper.Get(kid)
	if err != nil {
		return "", err
	}

	opt := (&jose.SignerOptions{}).WithType("JWT").WithHeader(headerKID, kid)
	key := jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: secret}
	sig, err := jose.NewSigner(key, opt)

	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	exp := now.Add(at.dur)

	c := claims{
		UserInfo: info,
		Scopes:   at.scp,
		Claims: jwt.Claims{
			Subject:   info.GetID(),
			Issuer:    at.iss,
			Audience:  jwt.Audience{at.aud},
			Expiry:    jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	return jwt.Signed(sig).Claims(c).CompactSerialize()
}

func (at accessToken) parse(tstr string) (*claims, error) {
	c := &claims{
		UserInfo: auth.NewUserInfo("", "", nil, nil),
	}

	jt, err := jwt.ParseSigned(tstr)
	if err != nil {
		return nil, err
	}

	if len(jt.Headers) == 0 {
		return nil, errors.New("strategies/jwt: : No headers found in JWT token")
	}

	if len(jt.Headers[0].KeyID) == 0 {
		return nil, ErrMissingKID
	}

	secret, alg, err := at.keeper.Get(jt.Headers[0].KeyID)

	if err != nil {
		return nil, err
	}

	if jt.Headers[0].Algorithm != alg {
		return nil, ErrInvalidAlg
	}

	if err := jt.Claims(secret, c); err != nil {
		return nil, err
	}

	return c, c.Validate(jwt.Expected{
		Time:     time.Now().UTC(),
		Issuer:   at.iss,
		Audience: jwt.Audience{at.aud},
	})
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
