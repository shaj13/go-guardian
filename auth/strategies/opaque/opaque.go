// Package opaque provides server-side consistent tokens.
//
// It generates tokens in a proprietary format that the
// client cannot access and contain some identifier to
// information in a server's persistent storage.
//
// It uses HMAC with SHA to generate and validate tokens.
package opaque

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
)

// SecretsKeeper hold all secrets/keys to sign and parse opaque token.
type SecretsKeeper interface {
	// Keys return's keys to sign and parse opaque token,
	// The Returned keys must be in descending order timestamp.
	Keys() ([][]byte, error)
}

// StaticSecret implements the SecretsKeeper and holds only a single secret.
type StaticSecret []byte

// Keys return's keys to sign and parse opaque token,
func (s StaticSecret) Keys() ([][]byte, error) {
	return [][]byte{s}, nil
}

// TokenStore is used to manage client tokens. Tokens are used for
// clients to authenticate, and each token is mapped to an applicable auth info.
type TokenStore interface {
	// Store used to store a new token entry.
	Store(context.Context, Token) error
	// Lookup used to get token entry by its signature.
	Lookup(ctx context.Context, signature string) (Token, error)
	// Revoke used to delete token entry by its signature.
	Revoke(ctx context.Context, signature string) error
}

// Token represent a token entry in token store.
type Token struct {
	// Lifespan represent when the token expires.
	Lifespan time.Time
	// Signature a unique HMAC, per token.
	//
	// Signature used to verify client token.
	//
	// Store the signature in plaintext without
	// any form of obfuscation or encryption.
	Signature string
	// Prefix represent token prefix or type.
	Prefix string
	// Info represent auth info token is mapped to it.
	Info auth.Info
}

// IssueToken issue token for the provided user info.
func IssueToken(
	ctx context.Context,
	info auth.Info,
	s TokenStore,
	k SecretsKeeper,
	opts ...auth.Option,
) (string, error) {
	return newOpaque(s, k, opts...).issue(ctx, info)
}

// GetAuthenticateFunc return function to authenticate request using opaque token.
// The returned function typically used with the token strategy.
func GetAuthenticateFunc(s TokenStore, k SecretsKeeper, opts ...auth.Option) token.AuthenticateFunc {
	return newOpaque(s, k, opts...).parse
}

// New return strategy authenticate request using opaque token.
//
// New is similar to:
//
//	fn := opaque.GetAuthenticateFunc(tokenStore, secretsKeeper, opts...)
//	token.New(fn, cache, opts...)
func New(c auth.Cache, s TokenStore, k SecretsKeeper, opts ...auth.Option) auth.Strategy {
	fn := GetAuthenticateFunc(s, k, opts...)
	return token.New(fn, c, opts...)
}

func newOpaque(s TokenStore, k SecretsKeeper, opts ...auth.Option) *opaque {
	o := &opaque{
		tokenLength: 24,
		prefix:      "s",
		exp:         time.Hour * 24,
		keeper:      k,
		store:       s,
		h:           crypto.SHA512_256,
	}

	for _, opt := range opts {
		opt.Apply(o)
	}

	return o
}

type opaque struct {
	tokenLength int
	prefix      string
	exp         time.Duration
	keeper      SecretsKeeper
	store       TokenStore
	h           crypto.Hash
}

func (o *opaque) issue(ctx context.Context, info auth.Info) (string, error) {
	id := make([]byte, o.tokenLength)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		return "", err
	}

	keys, err := o.keeper.Keys()

	if len(keys) == 0 || err != nil {
		return "", fmt.Errorf("strategies/opaque: no key to sign token %w", err)
	}

	signature := o.sign(keys[0], id)

	t := Token{
		Prefix:    o.prefix,
		Lifespan:  time.Now().Add(o.exp),
		Info:      info,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}

	if err := o.store.Store(ctx, t); err != nil {
		return "", err
	}

	mixed := append(id, signature...)
	return o.prefix + "." + base64.RawURLEncoding.EncodeToString(mixed), nil
}

func (o *opaque) parse(ctx context.Context, _ *http.Request, token string) (auth.Info, time.Time, error) {
	if len(token) <= (len(o.prefix) + o.tokenLength + 1) {
		return nil, time.Time{}, errors.New("strategies/opaque: token is too short")
	}

	if token[:len(o.prefix)] != o.prefix {
		return nil, time.Time{}, errors.New("strategies/opaque: invalid token prefix")
	}

	mixed, err := base64.RawURLEncoding.DecodeString(token[len(o.prefix)+1:])
	if err != nil {
		return nil, time.Time{}, err
	}

	keys, err := o.keeper.Keys()
	if len(keys) == 0 || err != nil {
		return nil, time.Time{}, fmt.Errorf("strategies/opaque: no key to sign token %w", err)
	}

	id := mixed[:o.tokenLength]
	signature := mixed[o.tokenLength:]
	ok := false

	for _, key := range keys {
		mac := o.sign(key, id)
		if ok = hmac.Equal(mac, signature); ok {
			break
		}
	}

	if !ok {
		return nil, time.Time{}, errors.New("strategies/opaque: invalid token signature")
	}

	t, err := o.store.Lookup(ctx, base64.RawURLEncoding.EncodeToString(signature))
	if err != nil {
		return nil, time.Time{}, err
	}

	if t.Lifespan.Before(time.Now()) {
		return nil, time.Time{}, errors.New("strategies/opaque: token is expired")
	}

	return t.Info, t.Lifespan, nil
}

func (o *opaque) sign(key, id []byte) []byte {
	hm := hmac.New(o.h.New, key)
	_, _ = hm.Write(id)
	return hm.Sum(nil)
}
