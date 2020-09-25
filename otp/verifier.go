package otp

import (
	"errors"
	"time"
)

// ErrMaxAttempts is returned by Verifier,
// When the verification failures count equal the max attempts.
var ErrMaxAttempts = errors.New("OTP: Max attempts reached, Account locked out")

// VerificationDisabledError is returned by Verifier
// when the password verification process disabled for a period of time.
type VerificationDisabledError time.Duration

// Error returns string describe verification process disabled for a period of time.
func (v VerificationDisabledError) Error() string {
	return "OTP: Password verification disabled, Try again in " + time.Duration(v).String()
}

// Verifier represents one-time password verification for both HOTP and TOTP.
type Verifier struct {
	// EnableLockout enable or disable lockout mechanism
	// Default true
	EnableLockout bool
	// LockOutStartAt define in what attempt number, lockout mechanism start to work.
	// Default  0
	LockOutStartAt uint
	// LockOutDelay define delay window to disable password verification process default 30
	// the formula is delay * failed Attempts as described in RFC 4226 section-7.3.
	LockOutDelay uint
	// MaxAttempts define max attempts of verification failures to lock the account default 3.
	MaxAttempts uint
	// RemainingAttempts represents the count of remaining verification attempts.
	remainingAttempts uint
	// Failures represents the count of verification failures.
	Failures uint
	// Skew define periods before or after the current counter to allow,
	// which allow compare OTPs not only with,
	// the receiving timestamp but also the past timestamps that are within,
	// the transmission delay, as described in RFC 6238 section-5.2
	// Default 1.
	//
	// Warning: A larger Skew would expose a larger window for attacks.
	Skew uint
	// DealyTime represents time until password verification process re-enabled.
	DealyTime time.Time
	// Key represnt Uri Format for OTP.
	Key *Key
}

func (v *Verifier) lockOut() error {

	if v.Failures == 0 {
		return nil
	}

	if v.Failures == v.MaxAttempts {
		return ErrMaxAttempts
	}

	if remaining := v.DealyTime.UTC().Sub(time.Now().UTC()); remaining > 0 {
		return VerificationDisabledError(remaining)
	}

	return nil
}

func (v *Verifier) updateLockOut(valid bool) {
	// if remainingAttempts and Failures is 0 means the Verifier its in the first iteration
	// so copy lockout start value and increment it by 1
	if v.remainingAttempts == 0 && v.Failures == 0 {
		v.remainingAttempts = v.LockOutStartAt + 1
	}

	if !v.EnableLockout || valid {
		v.remainingAttempts = v.LockOutStartAt + 1
		v.Failures = 0
		return
	}

	// remainingAttempts decrements target is 1,
	// remainingAttempts 0 reserved to detect the Verifier first iteration.
	// so this must be always grater than 2
	if v.remainingAttempts > 2 {
		v.remainingAttempts--
		return
	}

	v.Failures++
	v.DealyTime = time.Now().UTC().Add(time.Second * time.Duration(v.Failures*v.LockOutDelay))
}

func (v *Verifier) interval() uint64 {
	if v.Key.Type() == HOTP {
		counter := v.Key.Counter()
		counter++
		v.Key.SetCounter(counter)
		return counter
	}

	return uint64(time.Now().UTC().Unix()) / v.Key.Period()
}

// Verify one-time password.
func (v *Verifier) Verify(otp string) (bool, error) {
	err := v.lockOut()
	if err != nil {
		return false, err
	}

	generate := func(i uint64) (string, error) {
		return GenerateOTP(v.Key.Secret(), i, v.Key.Algorithm(), v.Key.Digits())
	}

	current := v.interval()
	intervals := []uint64{current}

	for i := 1; i <= int(v.Skew); i++ {
		intervals = append(intervals, current+uint64(i))
		if v := int64(current) - int64(i); v > -1 {
			intervals = append(intervals, uint64(v))
		}
	}

	for _, i := range intervals {
		code, err := generate(i)
		if err != nil {
			return false, err
		}

		if code == otp {
			return true, nil
		}
	}

	v.updateLockOut(false)
	return false, nil
}

// GenerateOTP return one time password or an error if occurs
// The Method is alias for GenerateOTP Function.
func (v *Verifier) GenerateOTP() (string, error) {
	return GenerateOTP(v.Key.Secret(), v.interval(), v.Key.Algorithm(), v.Key.Digits())
}

// New return's new Verifier, with defaults values.
func New(key *Key) *Verifier {
	v := new(Verifier)
	v.EnableLockout = true
	v.LockOutDelay = 30
	v.MaxAttempts = 3
	v.Key = key
	v.Skew = 1
	return v
}
