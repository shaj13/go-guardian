// Package basic provides authentication strategy,
// to authenticate HTTP requests using the standard basic scheme.
package basic

import (
	"context"
	"crypto/sha256"
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

// ExtensionKey represents a key for the hashed password in info extensions.
// Typically used when basic strategy cache the authentication decisions.
const ExtensionKey = "x-go-guardian-basic-hash"

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
	cache    store.Cache
	authFunc AuthenticateFunc
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
	hash, ok := ext[ExtensionKey]

	if !ok {
		return c.authenticatAndHash(ctx, r, userName, pass)
	}

	err = password(pass).compare(hash[0])
	return info, err
}

func (c *cachedBasic) authenticatAndHash(ctx context.Context, r *http.Request, userName, pass string) (auth.Info, error) { //nolint:lll
	info, err := c.authFunc(ctx, r, userName, pass)
	if err != nil {
		return nil, err
	}

	ext := info.Extensions()
	if ext == nil {
		ext = make(map[string][]string)
	}

	hash := password(pass).hash()
	ext[ExtensionKey] = []string{hash}
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
	cb := &cachedBasic{
		authFunc: f,
		cache:    cache,
	}

	return AuthenticateFunc(cb.authenticate)
}

type password string

func (p password) hash() string {
	sha := sha256.New()
	_, _ = sha.Write([]byte(p))
	sum := sha.Sum(nil)
	return hex.EncodeToString(sum)
}

func (p password) compare(hash string) error {
	if p.hash() == hash {
		return nil
	}
	return ErrInvalidCredentials
}
