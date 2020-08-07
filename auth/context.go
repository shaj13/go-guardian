package auth

import (
	"context"
	"net/http"
)

type userKey struct{}

// RequestWithUser Save user information in request context.
func RequestWithUser(info Info, r *http.Request) *http.Request {
	ctx := CtxWithUser(r.Context(), info)
	return r.WithContext(ctx)
}

// User return user information from request context.
func User(r *http.Request) Info {
	return UserFromCtx(r.Context())
}

// CtxWithUser Save user information in context.
func CtxWithUser(ctx context.Context, info Info) context.Context {
	return context.WithValue(ctx, userKey{}, info)
}

// UserFromCtx return user information from context.
func UserFromCtx(ctx context.Context) Info {
	v := ctx.Value(userKey{})
	if info, ok := v.(Info); ok {
		return info
	}
	return nil
}
