package TFA

import (
	"time"
)

type OTP interface {
	Interval() uint64
	Secret() string
	Algorithm() HashAlgorithm
	Digits() Digits
	Verify(otp string) (bool, error)
}

type baseOTP struct {
	interval  uint64
	secret    string
	digits    Digits
	algorithm HashAlgorithm
}

func (b *baseOTP) Interval() uint64         { return b.interval }
func (b *baseOTP) Secret() string           { return b.secret }
func (b *baseOTP) Digits() Digits           { return b.digits }
func (b *baseOTP) Algorithm() HashAlgorithm { return b.algorithm }

type totp struct {
	*baseOTP
	period uint64
}

func (t *totp) Verify(otp string) (bool, error) {
	t.interval = uint64(time.Now().UTC().Unix()) / t.period
	code, err := GeneratOTP(t)
	return code == otp, err
}

type hotp struct {
	*baseOTP
}

func (h *hotp) Verify(otp string) (bool, error) {
	h.interval++
	code, err := GeneratOTP(h)
	return code == otp, err
}

func newBaseOTP(secret string, digits Digits, interval uint64, algo HashAlgorithm) *baseOTP {
	return &baseOTP{
		secret:    secret,
		digits:    digits,
		algorithm: algo,
		interval:  interval,
	}
}

func newTOTP(base *baseOTP, period uint64) *totp {
	return &totp{
		baseOTP: base,
		period: period,
	}
}

func newHOTP(base *baseOTP) *hotp {
	return &hotp{
		baseOTP: base,
	}
}
