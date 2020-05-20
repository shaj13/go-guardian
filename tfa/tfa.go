// Package tfa (two-factor authentication) provides a simple, clean, and idiomatic way
// for generating and verifying one-time passwords
// for both HOTP and TOTP defined in RFC 4226 and 6238.
package tfa

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
)

var (
	// ErrWeakSecretSize is returned by GenerateSecret,
	// when input secret size does not meet RFC 4226 requirements.
	ErrWeakSecretSize = errors.New("Weak secret size, The shared secret MUST be at least 128 bits")

	// ErrInvalidOTPTypeE is returned by NewOTP when OTP type not equal TOTP or HOTP
	ErrInvalidOTPTypeE = errors.New("Invalid OTP type")

	// ErrMissingLabel is returned by NewOTP when label missing
	ErrMissingLabel = errors.New("Missing Label")
)

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

const (
	// SHA1 represents the SHA1 algorithm name.
	SHA1 = HashAlgorithm("SHA1")
	// SHA256 represents the SHA256 algorithm name.
	SHA256 = HashAlgorithm("SHA256")
	// SHA512 represents the SHA512 algorithm name.
	SHA512 = HashAlgorithm("SHA512")
)

// Digits represents the length of OTP.
type Digits int

// String describe Digits as a string
func (d Digits) String() string {
	return fmt.Sprintf("%d", d)
}

const (
	// SixDigits of OTP.
	SixDigits Digits = 6
	// EightDigits of OTP
	EightDigits Digits = 8
)

// OTPType represent OTP type (TOTP, HOTP)
type OTPType string

const (
	// TOTP represents totp, defined in RFC 6238
	TOTP = OTPType("totp")
	// HOTP represents hotp, defined in RFC 4266
	HOTP = OTPType("hotp")
)

// Key represnt Uri Format for OTP
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
type Key struct{ *url.URL }

// Type returns the type for the Key (totp, hotp).
func (k *Key) Type() OTPType {
	return OTPType(k.Host)
}

// Label returns the label for the Key.
func (k *Key) Label() string {
	return strings.TrimPrefix(k.Path, "/")
}

// Secret returns the secret for the Key.
func (k *Key) Secret() string {
	return k.Query().Get("secret")
}

// Digits returns the length of pin code.
func (k *Key) Digits() Digits {
	str := k.Query().Get("digits")
	d, err := strconv.Atoi(str)
	if err != nil {
		return SixDigits
	}
	return Digits(d)
}

// Issuer returns a string value indicating the provider or service.
func (k *Key) Issuer() string {
	return k.Query().Get("issuer")
}

// IssuerLabelPrefix returns a string value indicating the provider or service extracted from label.
func (k *Key) IssuerLabelPrefix() string {
	sub := strings.Split(k.Label(), ":")
	if len(sub) == 2 {
		return sub[0]
	}
	return ""
}

// AccountName returns the name of the user's account.
func (k *Key) AccountName() string {
	sub := strings.Split(k.Label(), ":")
	if len(sub) == 2 {
		return sub[1]
	}
	return ""
}

// Algorithm return the hashing Algorithm name
func (k *Key) Algorithm() HashAlgorithm {
	return HashAlgorithm(k.Query().Get("algorithm"))
}

// Period that a TOTP code will be valid for, in seconds. The default value is 30.
// if type not a topt the returned value is 0
func (k *Key) Period() uint64 {
	if k.Type() == TOTP {
		if period := k.Query().Get("period"); len(period) > 0 {
			p, err := strconv.ParseUint(period, 10, 64)
			if err != nil {
				return 30
			}
			return p
		}
		return 30
	}
	return 0
}

// Counter return initial counter value. for provisioning a key for use with HOTP
// // if type not a hopt the returned value is 0
func (k *Key) Counter() uint64 {
	if k.Type() == HOTP {
		if counter := k.Query().Get("counter"); len(counter) > 0 {
			p, _ := strconv.ParseUint(counter, 10, 64)
			return p
		}
	}
	return 0
}

// SetCounter set counter value.
// if type not a hopt the set operation ignored.
func (k *Key) SetCounter(count uint64) {
	if k.Type() == HOTP {
		q := k.Query()
		q.Set("counter", strconv.FormatUint(count, 10))
		k.RawQuery = q.Encode()
	}
}

// GenerateOTP return one time password or an error if occurs
// The function compliant with RFC 4226, and implemented as mentioned in section 5.3
// See https://tools.ietf.org/html/rfc4226#section-5.3
func GenerateOTP(otp OTP) (string, error) {
	secret := strings.ToUpper(otp.Secret())
	key, err := base32.StdEncoding.DecodeString(secret)

	if err != nil {
		return "", err
	}

	interval := make([]byte, 8)
	binary.BigEndian.PutUint64(interval, otp.Interval())

	hash := hmac.New(otp.Algorithm().Hasher(), key)
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
	code := int(binCode&0x7fffffff) % int(math.Pow10(int(otp.Digits())))

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

// OTPConfig represent configuration needed to create OTP instance.
type OTPConfig struct {
	// OTPType targted OTP (TOTP, HOTP)
	OTPType OTPType
	// LockOutStartAt define in what attempt number, lockout mechanism start work.
	// Default  0
	LockOutStartAt uint
	// EnableLockout enable or disable lockout mechanism
	EnableLockout bool
	// LockOutDelay define delay window o disable password verification process default 30
	// the formula is delay * failed Attempts as described in RFC 4226 section-7.3.
	LockOutDelay uint
	// MaxAttempts define max attempts of verification failures to lock the account default 3.
	MaxAttempts uint
	// Digits represents the length of OTP.
	Digits Digits
	// SecretSize represents the length of secret, default 20 bytes.
	SecretSize uint
	// Secret represents shared secret between client and server, if empty a new secret will be generated.
	Secret string
	// HashAlgorithm represents tha hash algorithm hmac use, default SHA1
	HashAlgorithm HashAlgorithm
	// Period represents time step in seconds used by TOTP, default 30 as descriped in  RFC 6238 section-4.1.
	Period uint64
	// Counter represents the incremental number used by HOTP.
	Counter uint64
	// Issuer represents  the provider or service.
	Issuer string
	// Label represents path in key uri
	Label string
}

// NewOTP return OTP instance and it's relevant Key or error if occurs.
func NewOTP(cfg *OTPConfig) (*Key, OTP, error) {
	var otp OTP
	vals := url.Values{}
	key := new(Key)
	base, err := newBaseOTP(cfg, key)

	if err != nil {
		return nil, nil, err
	}

	if len(cfg.Label) == 0 {
		return nil, nil, ErrMissingLabel
	}

	if len(cfg.Issuer) != 0 {
		vals.Set("issuer", cfg.Issuer)
	}

	if cfg.OTPType == TOTP {
		otp = &totp{baseOTP: base}
		vals.Set("period", strconv.FormatUint(cfg.Period, 10))
	} else if cfg.OTPType == HOTP {
		otp = &hotp{baseOTP: base}
		vals.Set("counter", strconv.FormatUint(cfg.Counter, 10))
	} else {
		return nil, nil, ErrInvalidOTPTypeE
	}

	vals.Set("digits", cfg.Digits.String())
	vals.Set("secret", cfg.Secret)
	vals.Set("algorithm", cfg.HashAlgorithm.String())

	url := &url.URL{
		Scheme:   "otpauth",
		Host:     string(cfg.OTPType),
		Path:     "/" + cfg.Label,
		RawQuery: vals.Encode(),
	}

	key.URL = url

	return key, otp, nil
}

// NewOTPFromKey parse raw key string and return OTP instance and it's relevant Key or error if occurs.
func NewOTPFromKey(raw string) (*Key, OTP, error) {
	url, err := url.Parse(raw)
	if err != nil {
		return nil, nil, err
	}

	key := &Key{url}

	cfg := &OTPConfig{
		Secret:        key.Secret(),
		Counter:       key.Counter(),
		OTPType:       key.Type(),
		Digits:        key.Digits(),
		HashAlgorithm: key.Algorithm(),
		Label:         key.Label(),
		Period:        key.Period(),
		SecretSize:    20,
		Issuer:        key.Issuer(),
	}

	return NewOTP(cfg)
}

func newBaseOTP(cfg *OTPConfig, key *Key) (*baseOTP, error) {
	if len(cfg.Secret) == 0 {
		var err error
		cfg.Secret, err = GenerateSecret(cfg.SecretSize)
		if err != nil {
			return nil, err
		}
	}

	if cfg.Digits == 0 {
		cfg.Digits = 6
	}

	if len(cfg.HashAlgorithm) == 0 {
		cfg.HashAlgorithm = SHA1
	}

	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 3
	}

	if cfg.LockOutDelay == 0 {
		cfg.LockOutDelay = 30
	}

	if cfg.Period == 0 {
		cfg.Period = 30
	}

	return &baseOTP{
		key:           key,
		enableLockout: cfg.EnableLockout,
		stratAt:       cfg.LockOutStartAt,
		maxAttempts:   cfg.MaxAttempts,
		dealy:         cfg.LockOutDelay,
	}, nil
}
