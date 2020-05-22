package auth

import (
	"errors"
	"net/http"
	"strings"

	gerrors "github.com/shaj13/go-guardian/errors"
)

var (
	// ErrNoMatch is returned by Authenticator when request not authenticated,
	// and all registered Strategies returned errors.
	ErrNoMatch = errors.New("authenticator: No authentication strategy matched")

	// ErrDisabledPath is a soft error similar to EOF.
	// returned by Authenticator when a attempting to authenticate request have a disabled path.
	// Authenticator return DisabledPath only to signal the caller.
	// The caller should continue the request flow, and never return the error to the end users.
	ErrDisabledPath = errors.New("authenticator: Disabled Path")

	// ErrNOOP is a soft error similar to EOF,
	// returned by strategies that have NoOpAuthenticate function to indicate there no op,
	// and signal authenticator to unauthenticate the request.
	ErrNOOP = errors.New("NOOP")
)

// Authenticator carry the registered authentication strategies,
// and represents the first API to authenticate received requests.
type Authenticator interface {
	// Authenticate dispatch the request to the registered authentication strategies,
	// and return user information from the first strategy that successfully authenticates the request.
	// Otherwise, an aggregated error returned.
	// if request attempt to visit a disabled path, ErrDisabledPath returned to signal the caller,
	// Otherwise, start the authentication process.
	// See ErrDisabledPath documentation for more info.
	//
	// NOTICE: Authenticate does not guarantee the order strategies run in.
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
	strategies map[StrategyKey]Strategy
	paths      map[string]struct{}
}

func (a *authenticator) Authenticate(r *http.Request) (Info, error) {
	// check if request to a disabled path
	if a.disabledPath(r.RequestURI) {
		return nil, ErrDisabledPath
	}

	errs := gerrors.MultiError{ErrNoMatch}

	for _, strategy := range a.strategies {
		info, err := strategy.Authenticate(r.Context(), r)
		if err == nil {
			return info, nil
		}
		errs = append(errs, err)
	}

	return nil, errs
}

func (a *authenticator) disabledPath(path string) bool {
	path = strings.TrimPrefix(path, "/")
	_, ok := a.paths[path]
	return ok
}

func (a *authenticator) Strategy(key StrategyKey) Strategy          { return a.strategies[key] }
func (a *authenticator) EnableStrategy(key StrategyKey, s Strategy) { a.strategies[key] = s }
func (a *authenticator) DisableStrategy(key StrategyKey)            { delete(a.strategies, key) }
func (a *authenticator) DisabledPaths() map[string]struct{}         { return a.paths }

// New return new Authenticator and disables authentication process at a given paths.
// The returned authenticator not safe for concurrent access.
func New(paths ...string) Authenticator {
	p := make(map[string]struct{})

	for _, path := range paths {
		path = strings.TrimPrefix(path, "/")
		p[path] = struct{}{}
	}

	return &authenticator{
		strategies: make(map[StrategyKey]Strategy),
		paths:      p,
	}
}
