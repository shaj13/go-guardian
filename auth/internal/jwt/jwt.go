package jwt

import (
	"crypto"
	"errors"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const headerKID = "kid"

var (
	// ErrMissingKID is returned by Authenticate Strategy method,
	// when failed to retrieve kid from token header.
	ErrMissingKID = errors.New("Token missing " + headerKID + " header")

	// ErrInvalidAlg is returned by Authenticate Strategy method,
	// when jwt token alg header does not match key algorithm.
	ErrInvalidAlg = errors.New("Invalid signing algorithm, token alg header does not match key algorithm")
)

// SecretsKeeper hold all secrets/keys to sign and parse JWT token
type SecretsKeeper interface {
	// KID return's secret/key id.
	// KID must return the most recently used id if more than one secret/key exists.
	// https://tools.ietf.org/html/rfc7515#section-4.1.4
	KID() string
	// Get return's secret/key and the corresponding sign algorithm.
	Get(kid string) (key interface{}, algorithm string, err error)
}

// IssueToken issue jwt access token from the given dest.
func IssueToken(k SecretsKeeper, dest ...interface{}) (string, error) {
	kid := k.KID()
	secret, alg, err := k.Get(kid)
	if err != nil {
		return "", err
	}

	opt := (&jose.SignerOptions{}).WithType("JWT").WithHeader(headerKID, kid)
	key := jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: secret}
	sig, err := jose.NewSigner(key, opt)

	if err != nil {
		return "", err
	}

	builder := jwt.Signed(sig)
	for _, v := range dest {
		builder = builder.Claims(v)
	}

	return builder.CompactSerialize()
}

// ParseToken parse jwt access token to the given dest.
func ParseToken(k SecretsKeeper, token string, dest ...interface{}) error {
	jt, err := jwt.ParseSigned(token)
	if err != nil {
		return err
	}

	if len(jt.Headers) == 0 {
		return errors.New("No headers found in JWT token")
	}

	if len(jt.Headers[0].KeyID) == 0 {
		return ErrMissingKID
	}

	secret, alg, err := k.Get(jt.Headers[0].KeyID)

	if err != nil {
		return err
	}

	if jt.Headers[0].Algorithm != alg {
		return ErrInvalidAlg
	}

	if v, ok := secret.(crypto.Signer); ok {
		secret = v.Public()
	}

	return jt.Claims(secret, dest...)
}
