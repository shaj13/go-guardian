// Package digest provides authentication strategy,
// to authenticate HTTP requests using the standard digest scheme as described in RFC 7616.
package digest

import (
	"context"
	"crypto"
	_ "crypto/md5" //nolint:gosec
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/shaj13/go-guardian/v2/auth"
)

// ErrInvalidResponse is returned by Strategy when client authz response does not match server hash.
var ErrInvalidResponse = errors.New("strategies/digest: Invalid Response")

// FetchUser a callback function to return the user password and user info.
type FetchUser func(userName string) (string, auth.Info, error)

// Digest authentication strategy.
type Digest struct {
	fn    FetchUser
	chash crypto.Hash
	c     auth.Cache
	h     Header
}

// Authenticate user request and returns user info, Otherwise error.
func (d *Digest) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	authz := r.Header.Get("Authorization")
	h := make(Header)

	if err := h.Parse(authz); err != nil {
		return nil, err
	}

	passwd, info, err := d.fn(h.UserName())
	if err != nil {
		return nil, err
	}

	HA1 := d.hash(h.UserName() + ":" + h.Realm() + ":" + passwd)
	HA2 := d.hash(r.Method + ":" + r.RequestURI)
	HKD := d.hash(HA1 + ":" + h.Nonce() + ":" + h.NC() + ":" + h.Cnonce() + ":" + h.QOP() + ":" + HA2)
	if subtle.ConstantTimeCompare([]byte(HKD), []byte(h.Response())) != 1 {
		return nil, ErrInvalidResponse
	}

	if _, ok := d.c.Load(h.Nonce()); !ok {
		return nil, ErrInvalidResponse
	}

	// validate the header values.
	ch := d.h.Clone()
	ch.SetNonce(h.Nonce())

	if err := ch.Compare(h); err != nil {
		return nil, err
	}

	return info, nil
}

// GetChallenge returns string indicates the authentication scheme.
// Typically used to adds a HTTP WWW-Authenticate header.
func (d *Digest) GetChallenge() string {
	h := d.h.Clone()
	str := h.WWWAuthenticate()
	d.c.Store(h.Nonce(), struct{}{})
	return str
}

func (d *Digest) hash(str string) string {
	h := d.chash.New()
	_, _ = h.Write([]byte(str))
	p := h.Sum(nil)
	return hex.EncodeToString(p)
}

// New returns digest authentication strategy.
// Digest strategy use MD5 as default hash.
// Digest use cache to store nonce.
func New(f FetchUser, c auth.Cache, opts ...auth.Option) *Digest {
	d := new(Digest)
	d.fn = f
	d.chash = crypto.MD5
	d.c = c
	d.h = make(Header)
	d.h.SetRealm("Users")
	d.h.SetAlgorithm("md5")
	d.h.SetOpaque(secretKey())

	for _, opt := range opts {
		opt.Apply(d)
	}

	return d
}
