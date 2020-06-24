package digest

import (
	"context"
	"net/http"

	"github.com/shaj13/go-guardian/auth"
	"github.com/shaj13/go-guardian/errors"
	"github.com/shaj13/go-guardian/store"
)

// CachedStrategy caches digest strategy authentication response based on authorization nonce field.
type CachedStrategy struct {
	*Strategy
	Cache store.Cache
}

// Authenticate user request and returns user info, Otherwise error.
func (c *CachedStrategy) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	authz := r.Header.Get("Authorization")
	h := make(Header)
	_ = h.Parse(authz)

	info, ok, err := c.Cache.Load(h.Nonce(), r)

	if err != nil {
		return nil, err
	}

	if !ok {
		info, err = c.Strategy.Authenticate(ctx, r)
		if err == nil {
			// cache result
			err = c.Cache.Store(h.Nonce(), info, r)
		}
	}

	if err != nil {
		return nil, err
	}

	if _, ok := info.(auth.Info); !ok {
		return nil, errors.NewInvalidType((*auth.Info)(nil), info)
	}

	return info.(auth.Info), nil
}
