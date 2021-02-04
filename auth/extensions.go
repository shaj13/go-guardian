package auth

// Extensions represents additional information to a user.
type Extensions map[string][]string

// Add adds the key, value pair to the extensions.
// It appends to any existing values associated with key.
// The key is case sensitive.
func (exts Extensions) Add(key, value string) {
	exts[key] = append(exts[key], value)
}

// Set sets the extensions entries associated with key to
// the single element value. It replaces any existing
// values associated with key.
func (exts Extensions) Set(key, value string) {
	exts[key] = []string{value}
}

// Del deletes the values associated with key.
func (exts Extensions) Del(key string) {
	delete(exts, key)
}

// Get gets the first value associated with the given key.
// It is case sensitive;
// If there are no values associated with the key, Get returns "".
func (exts Extensions) Get(key string) string {
	if exts == nil {
		return ""
	}
	v := exts[key]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// Values returns all values associated with the given key.
// It is case sensitive;
// The returned slice is not a copy.
func (exts Extensions) Values(key string) []string {
	if exts == nil {
		return nil
	}
	return exts[key]
}

// Has reports whether extensions has the provided key defined.
func (exts Extensions) Has(key string) bool {
	_, ok := exts[key]
	return ok
}

// Clone returns a copy of extensions or nil if extensions is nil.
func (exts Extensions) Clone() Extensions {
	if exts == nil {
		return nil
	}

	// Find total number of values.
	nv := 0
	for _, v := range exts {
		nv += len(v)
	}
	sv := make([]string, nv) // shared backing array for extensions values
	cloned := make(Extensions, len(exts))
	for k, v := range exts {
		n := copy(sv, v)
		cloned[k] = sv[:n:n]
		sv = sv[n:]
	}
	return cloned

}
