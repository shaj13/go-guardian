package TFA

import (
	"time"
)

type OTP interface {
	Interval() uint64
	SetInterval(i uint64)
	Secret() string
	Algorithm() HashAlgorithm
	Digits() int
	Verify(otp string) (bool, error)
}

type baseOTP struct {
	interval  uint64
	secret    string
	digits    int
	algorithm HashAlgorithm
}
func (b *baseOTP) Interval() uint64         { return b.interval }
func (b *baseOTP) Secret() string           { return b.secret }
func (b *baseOTP) Digits() int              { return b.digits }
func (b *baseOTP) Algorithm() HashAlgorithm { return b.algorithm }

type totp struct {
	*baseOTP
	period uint64
}

func (t *totp) Verify(otp string) (bool, error) {
	t.SetInterval(t.period)
	code, err := GeneratOTP(t)
	return code == otp, err
}

func (t *totp) SetInterval(i uint64) {
	t.period = i
	t.interval = uint64(time.Now().UTC().Unix()) / t.period
}

type hotp struct {
	*baseOTP
}

func (h *hotp) Verify(otp string) (bool, error) {
	h.SetInterval(h.interval + 1)
	code, err := GeneratOTP(h)
	return code == otp, err
}

func (h *hotp) SetInterval(i uint64) {
	h.interval = i
}

func newBaseOTP(secret string, digits int, algo HashAlgorithm) *baseOTP {
	return &baseOTP{
		secret:    secret,
		digits:    digits,
		algorithm: algo,
	}
}

func newTOTP(base *baseOTP) *totp {
	return &totp{
		baseOTP: base,
	}
}

func newHOTP(base *baseOTP) *hotp {
	return &hotp{
		baseOTP: base,
	}
}
