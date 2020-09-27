package auth

// Cache type describes the requirements for authentication strategies,
// that cache the authentication decisions.
type Cache interface {
	// Load returns key's value.
	Load(key interface{}) (interface{}, bool)
	// Store sets the value for a key.
	Store(key interface{}, value interface{})
	// Delete deletes the key value.
	Delete(key interface{})
}
