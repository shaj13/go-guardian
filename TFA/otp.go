package TFA

import (
	"fmt"
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
	interval      uint64
	secret        string
	enableLockout bool
	stratAt       uint
	stratAtB       uint
	digits        Digits
	dealy         uint
	maxAttempts   uint
	failed        uint
	dealyTime     time.Time
	algorithm     HashAlgorithm
}

func (b *baseOTP) Interval() uint64         { return b.interval }
func (b *baseOTP) Secret() string           { return b.secret }
func (b *baseOTP) Digits() Digits           { return b.digits }
func (b *baseOTP) Algorithm() HashAlgorithm { return b.algorithm }
func (b *baseOTP) lockOut() error {

	if b.failed == 0 {
		return nil
	}

	if b.failed == b.maxAttempts {
		return fmt.Errorf("Max attempts reached, Account locked out")
	}

	if remaining := b.dealyTime.UTC().Sub(time.Now().UTC()); remaining > 0 {
		return fmt.Errorf("Password verification disabled, Try again in %s", remaining)
	}

	return nil
}

func (b *baseOTP) updateLockOut(valid bool) {
	if !b.enableLockout || valid {
		b.stratAt = b.stratAtB
		return 
	}

	if b.stratAt > 1 {
		b.stratAt--
		return
	}

	b.failed++
	b.dealyTime = time.Now().UTC().Add(time.Second * time.Duration(b.failed*b.dealy))
}

type totp struct {
	*baseOTP
	period uint64
}

func (t *totp) Verify(otp string) (bool, error) {
	err := t.lockOut()
	if err != nil {
		return false, err
	}
	t.interval = uint64(time.Now().UTC().Unix()) / t.period
	code, err := GeneratOTP(t)
	result := code == otp
	t.updateLockOut(result)
	return result, err
}

type hotp struct {
	*baseOTP
}

func (h *hotp) Verify(otp string) (bool, error) {
	err := h.lockOut()
	if err != nil {
		return false, err
	}
	h.interval++
	code, err := GeneratOTP(h)
	result := code == otp
	h.updateLockOut(result)
	return result, err
}