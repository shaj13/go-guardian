package union

import (
	"context"
	"net/http"

	"github.com/m87carlson/go-guardian/v2/auth"
)

// MultiError represent multiple errors that occur when attempting to authenticate a request.
type MultiError []error

func (errs MultiError) Error() string {
	if len(errs) == 0 {
		return ""
	}

	str := ""
	for _, err := range errs {
		str += err.Error() + ", "
	}

	return "strategies/union: [" + str[:len(str)-2] + "]"
}

// Union implements authentication strategy,
// and consolidate a chain of strategies.
type Union interface {
	auth.Strategy
	// AuthenticateRequest authenticates the request using a chain of strategies.
	// AuthenticateRequest returns user info alongside the successful strategy.
	AuthenticateRequest(r *http.Request) (auth.Strategy, auth.Info, error)
	// Chain returns chain of strategies
	Chain() []auth.Strategy
}

type union []auth.Strategy

func (u union) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	_, info, err := u.AuthenticateRequest(r)
	return info, err
}

func (u union) AuthenticateRequest(r *http.Request) (auth.Strategy, auth.Info, error) {
	errs := MultiError{}
	for _, s := range u {
		info, err := s.Authenticate(r.Context(), r)
		if err == nil {
			return s, info, nil
		}
		errs = append(errs, err)
	}
	return nil, nil, errs
}

func (u union) Chain() []auth.Strategy {
	return u
}

// New returns new union strategy.
func New(strategies ...auth.Strategy) Union {
	return union(strategies)
}
