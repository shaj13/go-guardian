package otp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	k := &Key{}
	v := New(k)

	assert.True(t, v.EnableLockout)
	assert.Equal(t, v.Key, k)
	assert.Equal(t, v.MaxAttempts, uint(3))
	assert.Equal(t, v.LockOutDelay, uint(30))
}

func TestVerifierLockOut(t *testing.T) {
	v := &Verifier{}

	// Round #1 return nil when Failures = 0
	err := v.lockOut()
	assert.NoError(t, err)

	// Round #2 return err when Failures = MaxAttempts
	v.MaxAttempts = 1
	v.Failures = 1
	err = v.lockOut()
	assert.EqualError(t, err, ErrMaxAttempts.Error())

	// Round #3 return err when Password verification disabled
	v.MaxAttempts = 3
	v.Failures = 1
	v.DealyTime = time.Now().Add(time.Hour)
	err = v.lockOut()
	assert.Contains(t, err.Error(), "Password verification disabled")
}

func TestVerifierUpdateLockOut(t *testing.T) {
	v := &Verifier{}
	v.EnableLockout = true
	v.LockOutStartAt = 2
	v.LockOutDelay = 30

	// Round #1 reset failure when valid or lockout disabled
	v.updateLockOut(true)
	assert.Equal(t, v.remainingAttempts, uint(3))

	// Round #2 decrease RemainingAttempts
	v.updateLockOut(false)
	assert.Equal(t, v.remainingAttempts, uint(2))

	// Round #3 increase Failures and set delay time
	v.updateLockOut(false)
	assert.Equal(t, v.Failures, uint(1))
	assert.WithinDuration(t, v.DealyTime, time.Now().UTC(), time.Second*time.Duration(v.Failures*v.LockOutDelay))

}

func TestVerifierVerify(t *testing.T) {
	key := NewKey(HOTP, "label", "GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA")
	ver := New(key)
	ver.Failures = 3

	// Round #1 verify return error when lockout return error
	ok, err := ver.Verify("123")
	assert.Error(t, err)
	assert.False(t, ok)

	// Round #2 verify return false and update lockout
	ver = New(key)
	ok, err = ver.Verify("123")
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, ver.Failures, uint(1))

	// Round #3 verify return true
	ver = New(key)
	ok, err = ver.Verify("422283")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestLockOutE2E(t *testing.T) {
	// Round #1 check if verification disabled when lockout start from 0
	v := &Verifier{
		EnableLockout: true,
		LockOutDelay:  uint(30),
	}

	v.updateLockOut(false)
	err := v.lockOut()
	assert.Contains(t, err.Error(), "Password verification disabled")

	// Round #2 check if verification disabled when lockout start from 10
	v = &Verifier{
		EnableLockout:  true,
		LockOutStartAt: 10,
		LockOutDelay:   uint(30),
	}

	for i := 0; i < 9; i++ {
		v.updateLockOut(false)
		err = v.lockOut()
		assert.NoError(t, err)
	}

	v.updateLockOut(false)
	err = v.lockOut()
	assert.Contains(t, err.Error(), "Password verification disabled")

	// Round #3 check if verification disabled when failures grater than 0
	v = &Verifier{
		EnableLockout:  true,
		LockOutStartAt: 10,
		LockOutDelay:   uint(30),
		Failures:       1,
	}
	v.updateLockOut(false)
	err = v.lockOut()
	assert.Contains(t, err.Error(), "Password verification disabled")
}
