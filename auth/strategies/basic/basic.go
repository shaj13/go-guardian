// Package basic provide authentication strategy,
// to authenticate HTTP requests using the standard basic and digest schemes.
package basic

import (
	"context"
	"errors"
	"net/http"

	"github.com/shaj13/go-passport/auth"
)

// ErrMissingPrams is returned by Authenticate Strategy method,
// when failed to retrieve user credentials from request.
var ErrMissingPrams = errors.New("basic: Request missing BasicAuth")

// StrategyKey export identifier for the basic strategy,
// commonly used when enable/add strategy to go-passport authenticator.
const StrategyKey = auth.StrategyKey("Basic.Strategy")

// Authenticate decalre custom function to authenticate request using user credentials.
// the authenticate function invoked by Authenticate Strategy method after extracting user credentials
// to compare against DB or ather service, if extracting user credentials from request failed a nil info
// with ErrMissingPrams returned, Otherwise, return Authenticate invocation result.
type Authenticate func(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error)

// Authenticate implement Authenticate Strategy method, and return user info or an appropriate error.
func (auth Authenticate) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	user, pass, err := auth.credentials(r)

	if err != nil {
		return nil, err
	}

	return auth(ctx, r, user, pass)
}

func (auth Authenticate) credentials(r *http.Request) (string, string, error) {
	user, pass, ok := r.BasicAuth()

	if !ok {
		return "", "", ErrMissingPrams
	}

	return user, pass, nil
}
