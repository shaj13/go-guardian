// Package basic provides authentication strategy,
// to authenticate HTTP requests using the standard basic scheme.
package basic

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/shaj13/go-guardian/auth"
	gerrors "github.com/shaj13/go-guardian/errors"
	"github.com/shaj13/go-guardian/store"
)

// ErrMissingPrams is returned by Authenticate Strategy method,
// when failed to retrieve user credentials from request.
var ErrMissingPrams = errors.New("basic: Request missing BasicAuth")

// ErrInvalidCredentials is returned by Authenticate Strategy method,
// when user password is invalid.
var ErrInvalidCredentials = errors.New("basic: Invalid user credentials")

// StrategyKey export identifier for the basic strategy,
// commonly used when enable/add strategy to go-guardian authenticator.
const StrategyKey = auth.StrategyKey("Basic.Strategy")

// ExtensionKey represents a key for the password in info extensions.
// Typically used when basic strategy cache the authentication decisions.
const ExtensionKey = "x-go-guardian-basic-password"

// AuthenticateFunc declare custom function to authenticate request using user credentials.
// the authenticate function invoked by Authenticate Strategy method after extracting user credentials
// to compare against DB or other service, if extracting user credentials from request failed a nil info
// with ErrMissingPrams returned, Otherwise, return Authenticate invocation result.
type AuthenticateFunc func(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error)

// Authenticate implement Authenticate Strategy method, and return user info or an appropriate error.
func (auth AuthenticateFunc) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	user, pass, err := auth.credentials(r)

	if err != nil {
		return nil, err
	}

	return auth(ctx, r, user, pass)
}

// Challenge returns string indicates the authentication scheme.
// Typically used to adds a HTTP WWW-Authenticate header.
func (auth AuthenticateFunc) Challenge(realm string) string {
	return fmt.Sprintf(`Basic realm="%s", title="'Basic' HTTP Authentication Scheme"`, realm)
}

func (auth AuthenticateFunc) credentials(r *http.Request) (string, string, error) {
	user, pass, ok := r.BasicAuth()

	if !ok {
		return "", "", ErrMissingPrams
	}

	return user, pass, nil
}

type cachedBasic struct {
	AuthenticateFunc
	hash  crypto.Hash
	cache store.Cache
}

func (c *cachedBasic) authenticate(ctx context.Context, r *http.Request, userName, pass string) (auth.Info, error) { // nolint:lll
	v, ok, err := c.cache.Load(userName, r)

	if err != nil {
		return nil, err
	}

	// if info not found invoke user authenticate function
	if !ok {
		return c.authenticatAndHash(ctx, r, userName, pass)
	}

	if _, ok := v.(auth.Info); !ok {
		return nil, gerrors.NewInvalidType((*auth.Info)(nil), v)
	}

	info := v.(auth.Info)
	ext := info.Extensions()
	hashedPass, ok := ext[ExtensionKey]

	if !ok {
		return c.authenticatAndHash(ctx, r, userName, pass)
	}

	err = password(pass).compare(c.hash, hashedPass[0])
	return info, err
}

func (c *cachedBasic) authenticatAndHash(ctx context.Context, r *http.Request, userName, pass string) (auth.Info, error) { //nolint:lll
	info, err := c.AuthenticateFunc(ctx, r, userName, pass)
	if err != nil {
		return nil, err
	}

	ext := info.Extensions()
	if ext == nil {
		ext = make(map[string][]string)
	}

	hashedPass := password(pass).hash(c.hash)
	ext[ExtensionKey] = []string{hashedPass}
	info.SetExtensions(ext)

	// cache result
	if err := c.cache.Store(userName, info, r); err != nil {
		return nil, err
	}

	return info, nil
}

// New return new auth.Strategy.
// The returned strategy, caches the invocation result of authenticate function.
func New(f AuthenticateFunc, cache store.Cache) auth.Strategy {
	return NewWithOptions(f, cache)
}

// NewWithOptions return new auth.Strategy.
// The returned strategy, caches the invocation result of authenticate function.
func NewWithOptions(f AuthenticateFunc, cache store.Cache, opts ...auth.Option) auth.Strategy {
	cb := &cachedBasic{
		AuthenticateFunc: f,
		cache:            cache,
	}

	for _, opt := range opts {
		opt.Apply(cb)
	}

	return AuthenticateFunc(cb.authenticate)
}

// SetHash set the hashing algorithm to hash the user password.
func SetHash(h crypto.Hash) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if v, ok := v.(*cachedBasic); ok {
			v.hash = h
		}
	})
}

type password string

func (p password) hash(h crypto.Hash) string {
	// check if allow to hash, otherwise return plain password.
	if h < crypto.MD4 {
		return string(p)
	}

	hasher := h.New()
	_, _ = hasher.Write([]byte(p))
	sum := hasher.Sum(nil)
	return hex.EncodeToString(sum)
}

func (p password) compare(h crypto.Hash, hashedPass string) error {
	if p.hash(h) == hashedPass {
		return nil
	}
	return ErrInvalidCredentials
}
