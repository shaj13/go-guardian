package cache

// Option configures cache instance using the functional options paradigm
// popularized by Rob Pike and Dave Cheney.
// If you're unfamiliar with this style,
// see https://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html and
// https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis.
type Option interface {
	Apply(c Cache)
}

// OptionFunc implements Option interface.
type OptionFunc func(c Cache)

// Apply the configuration to the provided cache.
func (fn OptionFunc) Apply(c Cache) {
	fn(c)
}
