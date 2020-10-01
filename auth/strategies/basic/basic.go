// Package basic provides authentication strategy,
// to authenticate HTTP requests using the standard basic scheme.
package basic

import (
	"context"
	"errors"
	"net/http"

	"github.com/shaj13/go-guardian/v2/auth"
)

var (
	// ErrMissingPrams is returned by Authenticate Strategy method,
	// when failed to retrieve user credentials from request.
	ErrMissingPrams = errors.New("strategies/basic: Request missing BasicAuth")

	// ErrInvalidCredentials is returned by Authenticate Strategy method,
	// when user password is invalid.
	ErrInvalidCredentials = errors.New("strategies/basic: Invalid user credentials")
)

// AuthenticateFunc declare custom function to authenticate request using user credentials.
// the authenticate function invoked by Authenticate Strategy method after extracting user credentials
// to compare against DB or other service, if extracting user credentials from request failed a nil info
// with ErrMissingPrams returned, Otherwise, return Authenticate invocation result.
type AuthenticateFunc func(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error)

type basic struct {
	fn     AuthenticateFunc
	parser Parser
}

func (b basic) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	user, pass, err := b.parser.Credentials(r)
	if err != nil {
		return nil, err
	}
	return b.fn(ctx, r, user, pass)
}

// New return new auth.Strategy.
func New(fn AuthenticateFunc, opts ...auth.Option) auth.Strategy {
	b := new(basic)
	b.fn = fn
	b.parser = AuthorizationParser()
	for _, opt := range opts {
		opt.Apply(b)
	}
	return b
}
