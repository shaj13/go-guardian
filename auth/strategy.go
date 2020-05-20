package auth

import (
	"context"
	"net/http"
)

// StrStrategyKey define a custom type to expose a strategy identifier.
type StrategyKey string

// Strategy represents an authentication mechanism or method to authenticate users requests.
type Strategy interface {
	// Authenticate users requests and return user information or error.
	Authenticate(ctx context.Context, r *http.Request) (Info, error)
}
