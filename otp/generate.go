package otp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"strings"
)

// ErrWeakSecretSize is returned by GenerateSecret,
// when input secret size does not meet RFC 4226 requirements.
var ErrWeakSecretSize = errors.New("Weak secret size, The shared secret MUST be at least 128 bits")

// GenerateOTP return one time password or an error if occurs
// The function compliant with RFC 4226, and implemented as mentioned in section 5.3
// See https://tools.ietf.org/html/rfc4226#section-5.3
func GenerateOTP(secret string, counter uint64, algo HashAlgorithm, dig Digits) (string, error) {
	secret = strings.ToUpper(secret)
	key, err := base32.StdEncoding.DecodeString(secret)

	if err != nil {
		return "", err
	}

	interval := make([]byte, 8)
	binary.BigEndian.PutUint64(interval, counter)

	hash := hmac.New(algo.Hasher(), key)
	_, err = hash.Write(interval)

	if err != nil {
		return "", err
	}

	result := hash.Sum(nil)

	// Truncate logic performs Step 2 and Step 3 in RFC 4226 section 5.3
	var binCode uint32
	offset := result[len(result)-1] & 0xf
	reader := bytes.NewReader(result[offset : offset+4])
	err = binary.Read(reader, binary.BigEndian, &binCode)
	if err != nil {
		return "", err
	}

	// 0x7FFFFFFF mask is a number in hexadecimal (2,147,483,647 in decimal)
	// that represents the maximum positive value for a 32-bit signed binary integer.
	// The reason for masking the most significant bit of P is to avoid
	// confusion about signed vs. unsigned modulo computations.  Different
	// processors perform these operations differently, and masking out the
	// signed bit removes all ambiguity.
	code := int(binCode&0x7fffffff) % int(math.Pow10(int(dig)))

	return strconv.Itoa(code), nil
}

// GenerateSecret return base32 random generated secret.
// Size must be in bytes length, if size does not meet RFC 4226 requirements ErrWeakSecretSize returned.
func GenerateSecret(size uint) (string, error) {
	if size < 16 {
		return "", ErrWeakSecretSize
	}

	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	secret := make([]byte, size)
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}
	return encoder.EncodeToString(secret), nil
}
