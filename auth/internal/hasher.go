package internal

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"hash"
	"sync"
)

// Hasher represents a hash generator.
type Hasher interface {
	Hash(string) string
}

// PlainTextHasher implements the hasher interface and return input as is without hashing it.
type PlainTextHasher struct{}

// Hash return str as is without hashing it.
func (p PlainTextHasher) Hash(str string) string { return str }

// HMACHasher implements the hasher interface and hash input using HMAC hashing alg.
type HMACHasher struct {
	p *sync.Pool
}

// Hash str and return output as base64.
func (hm HMACHasher) Hash(str string) string {
	h := hm.p.Get().(hash.Hash)
	if _, err := h.Write([]byte(str)); err != nil {
		// Write() on hash never fails
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// NewHMACHasher return new hmac hasher instance.
func NewHMACHasher(h crypto.Hash, key []byte) *HMACHasher {
	return &HMACHasher{
		p: &sync.Pool{
			New: func() interface{} {
				return hmac.New(h.New, key)
			},
		},
	}
}
