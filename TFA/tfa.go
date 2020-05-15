package TFA

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
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
	// ErrWeakSecretSize is returned by GenerateSecret when input secret size does not meet RFC 4226 requirements.
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

const (
	SHA1   = HashAlgorithm("SHA1")
	SHA256 = HashAlgorithm("SHA256")
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
	TOTP = OTPType("totp")
	HOTP = OTPType("hotp")
)

// Key represnt Uri Format for OTP
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
type Key struct{ *url.URL }

// Type returns the type for the Key (totp, hotp).
func (k *Key) Type() string {
	return k.Host
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
	if k.Type() == "totp" {
		if period := k.Query().Get("period"); len(period) > 0 {
			p, _ := strconv.ParseUint(period, 10, 64)
			return p
		}
		return 30
	}
	return 0
}

// Counter return initial counter value. for provisioning a key for use with HOTP
// // if type not a hopt the returned value is 0
func (k *Key) Counter() uint64 {
	if k.Type() == "hotp" {
		if counter := k.Query().Get("counter"); len(counter) > 0 {
			p, _ := strconv.ParseUint(counter, 10, 64)
			return p
		}
	}
	return 0
}

// GenerateOTP return one time password or an error if occurs
// The function compliant with RFC 4226, and implemented as mentioned in section 5.3
// See https://tools.ietf.org/html/rfc4226#section-5.3
func GeneratOTP(otp OTP) (string, error) {
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

type OTPConfig struct {
	OTPType       OTPType
	Digits        Digits
	SecretSize    uint
	Secret        string
	HashAlgorithm HashAlgorithm
	Period        uint64
	Counter       uint64
	Issuer        string
	Label         string
}

func NewOTP(cfg *OTPConfig) (*Key, OTP, error) {
	var interval uint64
	vals := url.Values{}

	if len(cfg.Label) == 0 {
		return nil, nil, ErrMissingLabel
	}

	if len(cfg.Secret) == 0 {
		var err error
		cfg.Secret, err = GenerateSecret(cfg.SecretSize)
		if err != nil {
			return nil, nil, err
		}
	}

	if cfg.Digits == 0 {
		cfg.Digits = 6
	}

	if len(cfg.HashAlgorithm) == 0 {
		cfg.HashAlgorithm = SHA1
	}

	if cfg.Period == 0 {
		cfg.Period = 30
	}

	if len(cfg.Issuer) != 0 {
		vals.Set("issuer", cfg.Issuer)
	}

	vals.Set("digits", cfg.Digits.String())
	vals.Set("secret", cfg.Secret)

	if cfg.OTPType == TOTP {
		interval = cfg.Period
		vals.Set("period", strconv.FormatUint(uint64(cfg.Period), 10))
	} else if cfg.OTPType == HOTP {
		interval = cfg.Counter
		vals.Set("counter", strconv.FormatUint(uint64(cfg.Counter), 10))
	} else {
		return nil, nil, ErrInvalidOTPTypeE
	}

	url := &url.URL{
		Scheme:   "otpauth",
		Host:     string(cfg.OTPType),
		Path:     "/" + cfg.Label,
		RawQuery: vals.Encode(),
	}

	key := &Key{URL: url}
	base := newBaseOTP(cfg.Secret, cfg.Digits, interval, cfg.HashAlgorithm)

	if cfg.OTPType == TOTP {
		return key, newTOTP(base, cfg.Period), nil
	}

	return key, newHOTP(base), nil
}
