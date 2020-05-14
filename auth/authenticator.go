package auth

import (
	"context"
	"errors"
	"net/http"
)

var (
	ErrNoMatch      = errors.New("authenticator: No authentication strategy matched to request all Strategies returned errors")
	// ErrMissingPrams = errors.New("authenticator: Missing authentication parameters")
)

type StrategyKey string

type Strategies map[StrategyKey]Strategy

type Strategy interface {
	Authenticate(ctx context.Context, r *http.Request) (Info, error)
}

type Authenticator interface {
	Authenticate(r *http.Request) (Info, error)
	Strategies() Strategies
	SetStrategies(Strategies)
	EnableStrategy(key StrategyKey, strategy Strategy)
	DisableStrategy(key StrategyKey)
}

type authenticator struct {
	strategies Strategies
}

func (a *authenticator) Authenticate(r *http.Request) (Info, error) {
	errs := authError{ErrNoMatch}

	for _, s := range a.strategies {
		info, err := s.Authenticate(r.Context(), r)
		if err == nil {
			return info, nil
		}
		errs = append(errs, err)
	}

	return nil, errs
}

func (a *authenticator) Strategies() Strategies                     { return a.strategies }
func (a *authenticator) SetStrategies(s Strategies)                 { a.strategies = s }
func (a *authenticator) EnableStrategy(key StrategyKey, s Strategy) { a.strategies[key] = s }
func (a *authenticator) DisableStrategy(key StrategyKey)            { delete(a.strategies, key) }

func New() Authenticator {
	a := new(authenticator)
	a.strategies = make(map[StrategyKey]Strategy)
	return a
}
