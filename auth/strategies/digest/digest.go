// Package digest provides authentication strategy,
// to authenticate HTTP requests using the standard digest scheme as described in RFC 7616.
package digest

import (
	"context"
	"encoding/hex"
	"hash"
	"net/http"

	"github.com/shaj13/go-guardian/auth"
	"github.com/shaj13/go-guardian/errors"
)

// StrategyKey export identifier for the digest strategy,
// commonly used when enable/add strategy to go-guardian authenticator.
const StrategyKey = auth.StrategyKey("Digest.Strategy")

// ErrInvalidResponse is returned by Strategy when client authz response does not match server hash.
var ErrInvalidResponse = errors.New("Digest: Invalid Response")

// Strategy implements auth.Strategy and represents digest authentication as described in RFC 7616.
type Strategy struct {
	// Hash a callback function to return the desired hash algorithm,
	// the passed algo args is extracted from authorization header
	// and if it missing the args will be same as algorithm field provided to the strategy.
	Hash func(algo string) hash.Hash

	// FetchUser a callback function to return the user password and user info or error in case of occurs.
	FetchUser func(userName string) (string, auth.Info, error)

	Realm     string
	Algorithm string
}

// Authenticate user request and returns user info, Otherwise error.
func (s *Strategy) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	authz := r.Header.Get("Authorization")
	h := make(Header)

	if err := h.Parse(authz); err != nil {
		return nil, err
	}

	passwd, info, err := s.FetchUser(h.UserName())

	if err != nil {
		return nil, err
	}

	algo := h.Algorithm()
	if len(algo) == 0 {
		algo = s.Algorithm
	}

	HA1 := s.hash(algo, h.UserName()+":"+h.Realm()+":"+passwd)
	HA2 := s.hash(algo, r.Method+":"+r.RequestURI)
	HKD := s.hash(algo, HA1+":"+h.Nonce()+":"+h.NC()+":"+h.Cnonce()+":"+h.QOP()+":"+HA2)

	if HKD != h.Response() {
		return nil, ErrInvalidResponse
	}

	return info, nil
}

func (s *Strategy) hash(algo, str string) string {
	h := s.Hash(algo)
	_, _ = h.Write([]byte(str))
	p := h.Sum(nil)
	return hex.EncodeToString(p)
}

// WWWAuthenticate set HTTP WWW-Authenticate header field with Digest scheme.
func (s *Strategy) WWWAuthenticate(hh http.Header) error {
	h := make(Header)
	h.SetRealm(s.Realm)
	h.SetAlgorithm(s.Algorithm)

	str, err := h.WWWAuthenticate()
	if err != nil {
		return err
	}

	hh.Set("WWW-Authenticate", str)
	return nil
}
