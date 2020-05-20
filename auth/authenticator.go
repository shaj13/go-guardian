package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
)

// ErrNoMatch is returned by Authenticator when request not authenticated, and all registered Strategies returned errors.
var ErrNoMatch = errors.New("authenticator: No authentication strategy matched to request all Strategies returned errors")

// DisabledPath is the error returned by Authenticator when a attempting to authenticate request have a disabled path.
// Authenticator return DisabledPath only to signal the caller. and it's a soft error similar to EOF.
// The caller should continue the request flow, and never return the error to the end users.
var DisabledPath = errors.New("authenticator: Disabled Path")

// StrStrategyKey define a custom type to expose a strategy identifier.
type StrategyKey string

// Strategy represents an authentication mechanism or method to authenticate users requests.
type Strategy interface {
	// Authenticate users requests and return user information or error.
	Authenticate(ctx context.Context, r *http.Request) (Info, error)
}

// Authenticator carry the registered authentication strategies, and represents the first API to authenticate received requests.
type Authenticator interface {
	// Authenticate dispatch the request to the registered authentication strategies,
	// and return user information from the first strategy that successfully authenticates the request.
	// Otherwise, an aggregated error returned.
	// if request attempt to visit a disabled path, error DisabledPath returned to signal the caller,
	// Otherwise, start the authentication process.
	// See DisabledPath documentation for more info.
	Authenticate(r *http.Request) (Info, error)
	// EnableStrategy register a new strategy to the authenticator.
	EnableStrategy(key StrategyKey, strategy Strategy)
	// DisableStrategy unregister a strategy from the authenticator.
	DisableStrategy(key StrategyKey)
	// Strategy return a registered strategy, Otherwise, nil.
	Strategy(key StrategyKey) Strategy
	// DisabledPaths return a map[string]struct{} represents a paths disabled from authentication.
	// Typically the paths are given during authenticator initialization.
	DisabledPaths() map[string]struct{}
}

type authenticator struct {
	strategies *sync.Map
	paths      map[string]struct{}
}

func (a *authenticator) Authenticate(r *http.Request) (Info, error) {
	// check if request to a disabled path
	if a.disabledPath(r.RequestURI) {
		return nil, DisabledPath
	}

	var info Info
	authenticated := false
	errs := authError{ErrNoMatch}

	a.strategies.Range(func(key, value interface{}) bool {
		strategy := value.(Strategy)
		result, err := strategy.Authenticate(r.Context(), r)
		if err == nil {
			info = result
			authenticated = true
			return false
		}
		errs = append(errs, err)
		return true
	})

	if authenticated {
		return info, nil
	}

	return nil, errs
}

func (a *authenticator) Strategy(key StrategyKey) Strategy {
	v, ok := a.strategies.Load(key)
	if !ok {
		return nil
	}
	return v.(Strategy)
}

func (a *authenticator) disabledPath(path string) bool {
	path = strings.TrimPrefix(path, "/")
	_, ok := a.paths[path]
	return ok
}

func (a *authenticator) EnableStrategy(key StrategyKey, s Strategy) { a.strategies.Store(key, s) }
func (a *authenticator) DisableStrategy(key StrategyKey)            { a.strategies.Delete(key) }
func (a *authenticator) DisabledPaths() map[string]struct{}         { return a.paths }

// New return new Authenticator and disables authentication process at a given paths.
func New(paths ...string) Authenticator {
	p := make(map[string]struct{})

	for _, path := range paths {
		path = strings.TrimPrefix(path, "/")
		p[path] = struct{}{}
	}

	return &authenticator{
		strategies: &sync.Map{},
		paths:      p,
	}
}
