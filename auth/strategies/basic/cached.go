package basic

import (
	"context"
	"errors"
	"net/http"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/internal"
)

// ExtensionKey represents a key for the password in info extensions.
// Typically used when basic strategy cache the authentication decisions.
//
// Deprecated: No longer used.
const ExtensionKey = "x-go-guardian-basic-password"

// ErrKeyInvalidType is returned by Revoke method, if the key is not a string.
var ErrKeyInvalidType = errors.New("strategies/basic: cannot revoke a non-string key")

// NewCached return new auth.Strategy.
// The returned strategy, caches the invocation result of authenticate function.
func NewCached(f AuthenticateFunc, cache auth.Cache, opts ...auth.Option) auth.Strategy {
	cb := new(cachedBasic)
	cb.fn = f
	cb.cache = cache
	cb.comparator = plainText{}
	cb.hasher = internal.PlainTextHasher{}
	for _, opt := range opts {
		opt.Apply(cb)
	}

	basic := New(cb.authenticate, opts...)
	SetRevoker(CacheRevocation(cb)).Apply(basic)

	return basic
}

type entry struct {
	password string
	info     auth.Info
}

type cachedBasic struct {
	fn         AuthenticateFunc
	comparator Comparator
	cache      auth.Cache
	hasher     internal.Hasher
}

func (c *cachedBasic) authenticate(ctx context.Context, r *http.Request, userName, pass string) (auth.Info, error) { // nolint:lll
	hash := c.hasher.Hash(userName)
	v, ok := c.cache.Load(hash)

	// if info not found invoke user authenticate function
	if !ok {
		return c.authenticatAndHash(ctx, r, hash, userName, pass)
	}

	ent, ok := v.(entry)
	if !ok {
		return nil, auth.NewTypeError("strategies/basic:", entry{}, v)
	}

	return ent.info, c.comparator.Compare(ent.password, pass)
}

func (c *cachedBasic) authenticatAndHash(ctx context.Context, r *http.Request, hash string, userName, pass string) (auth.Info, error) { //nolint:lll
	info, err := c.fn(ctx, r, userName, pass)
	if err != nil {
		return nil, err
	}

	hashedPass, _ := c.comparator.Hash(pass)
	ent := entry{
		password: hashedPass,
		info:     info,
	}
	c.cache.Store(hash, ent)

	return info, nil
}

// Revoke is the actual implementation of revoking a user from the cached basic strategy.
func (c *cachedBasic) Revoke(key interface{}) error {
	s, ok := key.(string)
	if !ok {
		return ErrKeyInvalidType
	}
	hashed := c.hasher.Hash(s)
	c.cache.Delete(hashed)
	return nil
}
