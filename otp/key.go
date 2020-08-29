package otp

import (
	"net/url"
	"strconv"
	"strings"
)

// Key represnt Uri Format for OTP
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
type Key struct{ *url.URL }

// Type returns the type for the Key (totp, hotp).
func (k *Key) Type() Type {
	return Type(k.Host)
}

// SetType vaule in key.
func (k *Key) SetType(t Type) {
	k.Host = string(t)
}

// Label returns the label for the Key.
func (k *Key) Label() string {
	return strings.TrimPrefix(k.Path, "/")
}

// SetLabel value in key.
func (k *Key) SetLabel(label string) {
	k.Path = "/" + label
}

// Secret returns the secret for the Key.
func (k *Key) Secret() string {
	return k.Query().Get("secret")
}

// SetSecret value in key.
func (k *Key) SetSecret(secret string) {
	q := k.Query()
	q.Set("secret", secret)
	k.RawQuery = q.Encode()
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

// SetDigits value in key.
func (k *Key) SetDigits(d Digits) {
	q := k.Query()
	q.Set("digits", d.String())
	k.RawQuery = q.Encode()
}

// Issuer returns a string value indicating the provider or service.
func (k *Key) Issuer() string {
	return k.Query().Get("issuer")
}

// SetIssuer value in key.
func (k *Key) SetIssuer(issuer string) {
	q := k.Query()
	q.Set("issuer", issuer)
	k.RawQuery = q.Encode()
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
	algo := k.Query().Get("algorithm")
	if algo == "" {
		return SHA1
	}
	return HashAlgorithm(algo)
}

// SetAlgorithm set hash algorithm in key.
func (k *Key) SetAlgorithm(algo HashAlgorithm) {
	q := k.Query()
	q.Set("algorithm", algo.String())
	k.RawQuery = q.Encode()
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

// SetPeriod value in key.
// if type not a hopt the set operation ignored.
func (k *Key) SetPeriod(p uint64) {
	if k.Type() == TOTP {
		q := k.Query()
		q.Set("period", strconv.FormatUint(p, 10))
		k.RawQuery = q.Encode()
	}
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

// SetCounter value in key .
// if type not a hopt the set operation ignored.
func (k *Key) SetCounter(count uint64) {
	if k.Type() == HOTP {
		q := k.Query()
		q.Set("counter", strconv.FormatUint(count, 10))
		k.RawQuery = q.Encode()
	}
}

// NewKey return's new Key.
func NewKey(t Type, label, secret string) *Key {
	key := new(Key)
	key.URL = &url.URL{
		Scheme: "otpauth",
	}

	key.SetType(t)
	key.SetLabel(label)
	key.SetSecret(secret)

	return key
}

// NewKeyFromRaw return's key from raw string.
func NewKeyFromRaw(raw string) (*Key, error) {
	url, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	key := &Key{url}
	return key, nil
}
