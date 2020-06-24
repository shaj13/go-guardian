package digest

import (
	"context"
	"net/http"

	"github.com/shaj13/go-guardian/auth"
	"github.com/shaj13/go-guardian/errors"
	"github.com/shaj13/go-guardian/store"
)

const extensionKey = "x-go-guardian-digest"

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
		info, err := c.Strategy.Authenticate(ctx, r)

		if err != nil {
			return nil, err
		}

		ext := info.Extensions()
		if ext == nil {
			ext = make(map[string][]string)
		}

		ext[extensionKey] = []string{h.String()}
		info.SetExtensions(ext)

		// cache result
		err = c.Cache.Store(h.Nonce(), info, r)

		return info, err
	}

	v, ok := info.(auth.Info)

	if !ok {
		return nil, errors.NewInvalidType((*auth.Info)(nil), info)
	}

	sh := make(Header)
	_ = sh.Parse(v.Extensions()[extensionKey][0])

	h.SetNC("00000001")
	h.SetURI(r.RequestURI)
	sh.SetNC("00000001")
	sh.SetURI(r.RequestURI)

	if err := sh.Compare(h); err != nil {
		return nil, err
	}

	return v, nil
}
