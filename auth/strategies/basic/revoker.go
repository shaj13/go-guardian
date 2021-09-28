package basic

// Revoker revokes users from cache store.
type Revoker interface {
	Revoke(key interface{}) error
}

type revokeFn func(key interface{}) error

func (fn revokeFn) Revoke(key interface{}) error {
	return fn(key)
}

// CacheRevocation returns the cached basic authentication strategy as a Revoker.
func CacheRevocation(cb *cachedBasic) Revoker {
	fn := cb.Revoke
	return revokeFn(fn)
}
