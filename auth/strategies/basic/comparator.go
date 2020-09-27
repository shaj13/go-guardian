package basic

import (
	"crypto"
	"crypto/subtle"
	"encoding/hex"
)

// Comparator is the interface implemented by types,
// that can generate password hash and compares the hashed password
// with its possible plaintext equivalent
type Comparator interface {
	Hash(password string) (string, error)
	Compare(hashedPassword, password string) error
}

type basicHashing struct {
	h crypto.Hash
}

func (b basicHashing) Hash(password string) (string, error) {
	hasher := b.h.New()
	_, _ = hasher.Write([]byte(password))
	sum := hasher.Sum(nil)
	return hex.EncodeToString(sum), nil
}

func (b basicHashing) Compare(hashedPassword, password string) error {
	hash, err := b.Hash(password)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare([]byte(hash), []byte(hashedPassword)) == 1 {
		return nil
	}

	return ErrInvalidCredentials
}

type plainText struct{}

func (p plainText) Hash(password string) (string, error) {
	return password, nil
}

func (p plainText) Compare(hashedPassword, password string) error {
	if subtle.ConstantTimeCompare([]byte(hashedPassword), []byte(password)) == 1 {
		return nil
	}
	return ErrInvalidCredentials
}
