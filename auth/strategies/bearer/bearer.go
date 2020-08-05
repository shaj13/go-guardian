// Package bearer provides authentication strategy,
// to authenticate HTTP requests based on the bearer token.
//
// Deprecated: Use token Strategy instead.
package bearer

import (
	"context"
	"net/http"

	"github.com/shaj13/go-guardian/auth"
	"github.com/shaj13/go-guardian/auth/strategies/token"
	"github.com/shaj13/go-guardian/store"
)

var (
	// ErrInvalidToken indicate a hit of an invalid bearer token format.
	// And it's returned by Token function.
	ErrInvalidToken = token.ErrInvalidToken
	// ErrTokenNotFound is returned by authenticating functions for bearer strategies,
	// when token not found in their store.
	ErrTokenNotFound = token.ErrTokenNotFound
)

const (
	// CachedStrategyKey export identifier for the cached bearer strategy,
	// commonly used when enable/add strategy to go-guardian authenticator.
	CachedStrategyKey = token.CachedStrategyKey
	// StatitcStrategyKey export identifier for the static bearer strategy,
	// commonly used when enable/add strategy to go-guardian authenticator.
	StatitcStrategyKey = token.StatitcStrategyKey
)

// AuthenticateFunc declare custom function to authenticate request using token.
// The authenticate function invoked by Authenticate Strategy method when
// The token does not exist in the cahce and the invocation result will be cached, unless an error returned.
// Use NoOpAuthenticate instead to refresh/mangae token directly using cache or Append function.
type AuthenticateFunc = token.AuthenticateFunc

// Static implements auth.Strategy and define a synchronized map honor all predefined bearer tokens.
type Static = token.Static

// Token return bearer token from Authorization header, or ErrInvalidToken,
// The returned token will not contain "Bearer" keyword
func Token(r *http.Request) (string, error) {
	return token.AuthorizationParser("Bearer").Token(r)
}

// NewStaticFromFile returns static auth.Strategy, populated from a CSV file.
func NewStaticFromFile(path string) (auth.Strategy, error) {
	return token.NewStaticFromFile(path)
}

// NewStatic returns static auth.Strategy, populated from a map.
func NewStatic(tokens map[string]auth.Info) auth.Strategy {
	return token.NewStatic(tokens)
}

// New return new auth.Strategy.
// The returned strategy, caches the invocation result of authenticate function, See AuthenticateFunc.
// Use NoOpAuthenticate to refresh/mangae token directly using cache or Append function, See NoOpAuthenticate.
func New(auth AuthenticateFunc, c store.Cache) auth.Strategy {
	return token.New(auth, c)
}

// NoOpAuthenticate implements Authenticate function, it return nil, auth.ErrNOOP,
// commonly used when token refreshed/mangaed directly using cache or Append function,
// and there is no need to parse token and authenticate request.
func NoOpAuthenticate(ctx context.Context, r *http.Request, token string) (auth.Info, error) {
	return nil, auth.ErrNOOP
}
