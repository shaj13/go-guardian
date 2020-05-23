package auth

import (
	"context"
	"net/http"
)

type userKey struct{}

// RequestWithUser Save user information in request context.
func RequestWithUser(info Info, r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), userKey{}, info)
	return r.WithContext(ctx)
}

// User return user information from request context.
func User(r *http.Request) Info {
	v := r.Context().Value(userKey{})
	if info, ok := v.(Info); ok {
		return info
	}
	return nil
}
