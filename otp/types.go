package otp

import (
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

const (
	// SHA1 represents the SHA1 algorithm name.
	SHA1 = HashAlgorithm("SHA1")
	// SHA256 represents the SHA256 algorithm name.
	SHA256 = HashAlgorithm("SHA256")
	// SHA512 represents the SHA512 algorithm name.
	SHA512 = HashAlgorithm("SHA512")
)

const (
	// SixDigits of OTP.
	SixDigits Digits = 6
	// EightDigits of OTP
	EightDigits Digits = 8
)

const (
	// TOTP represents totp, defined in RFC 6238
	TOTP = Type("totp")
	// HOTP represents hotp, defined in RFC 4266
	HOTP = Type("hotp")
)

// Type represent OTP type (TOTP, HOTP)
type Type string

// HashAlgorithm represents the hashing function to use in the HMAC
type HashAlgorithm string

// Hasher returns a function create new hash.Hash.
func (h HashAlgorithm) Hasher() func() hash.Hash {
	return map[HashAlgorithm]func() hash.Hash{
		SHA1:   sha1.New,
		SHA256: sha256.New,
		SHA512: sha512.New,
	}[h]
}

// String describe HashAlgorithm as string
func (h HashAlgorithm) String() string {
	return string(h)
}

// Digits represents the length of OTP.
type Digits int

// String describe Digits as a string
func (d Digits) String() string {
	return fmt.Sprintf("%d", d)
}
