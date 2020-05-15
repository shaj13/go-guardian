package TFA

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"time"
)

type OTP interface {
	Interval() uint64
	SetInterval(i uint64) 
	Secret() string
	Hasher() func() hash.Hash
	Digits() int
	Verify(otp string) (bool, error)
}

type baseOTP struct {
	interval uint64
	secret   string
	digits   int
}

func (b *baseOTP) Interval() uint64 {
	return b.interval
}

func (b *baseOTP) Secret() string {
	return b.secret
}

func (b *baseOTP) Digits() int {
	return b.digits
}

type totp struct {
	*baseOTP
	algorithm HashAlgorithm
}

func (t *totp) Verify(otp string) (bool, error) {
	code, err := GeneratCode(t)
	return code == otp, err
}

func (t *totp) SetInterval(i uint64) {
	t.interval = uint64(time.Now().UTC().Unix())
}

func (t *totp) Hasher() func() hash.Hash {
	switch t.algorithm {
	case SHA1:
		return sha1.New
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	}
	return nil
}

type hotp struct {
	*baseOTP
}

func (h *hotp) Verify(otp string) (bool, error) {
	h.SetInterval(h.interval+1)
	code, err := GeneratCode(h)
	return code == otp, err
}

func (h *hotp) Hasher() func() hash.Hash {
	return sha1.New
}

func (h *hotp) SetInterval(i uint64) {
	h.interval = i
}

func newBaseOTP( secret string, digits int) *baseOTP {
	return &baseOTP{
		secret: secret,
		digits: digits,
	}
}

func newTOTP(base *baseOTP, algo HashAlgorithm) *totp { 
	return &totp{
		baseOTP: base,
		algorithm: algo,
	}
}

func newHOTP(base *baseOTP) *hotp {
	return &hotp{
		baseOTP: base,
	}
}