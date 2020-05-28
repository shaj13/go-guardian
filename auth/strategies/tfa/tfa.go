package tfa

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/shaj13/go-guardian/auth"
	gerrors "github.com/shaj13/go-guardian/errors"
	"github.com/shaj13/go-guardian/store"
	"github.com/shaj13/go-guardian/tfa"
)

var (
	// ErrMissingHeader is returned by strategy,
	// When the specified header in Config does not exist in the request.
	ErrMissingHeader = errors.New("TFA: Request Header Missing or Empty")

	// ErrInvalidOTP is returned by strategy,
	// When the user-supplied an invalid OTP and verification process failed.
	ErrInvalidOTP = errors.New("TFA: Invalid one time password")
)

// UserConfig represent TFA configuration for the end user.
type UserConfig struct {
	// Enabled indicate that user enable TFA for his account.
	Enabled bool
	// Failed represents count of failed verification.
	Failed uint
	// DelayTime represents the end of the disabling password verification process
	DelayTime time.Time
	// Key represents Raw Uri Format for OTP.
	// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	Key string
}

// Resource load and store user two factor data/configuration.
type Resource interface {
	// Load return user two factor data/configuration Where,
	// Enabled indicate that user enable TFA for his account,
	// Failed represents count of failed verification,
	// DelayTime represents the end of the disabling password verification process
	// Key represents Raw Uri Format for OTP See https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
	Load(username string) (Enabled bool, Failed uint, DelayTime time.Time, Key string)
	// Store user two factor data/configuration Where,
	// Key represents Raw Uri Format for OTP See https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
	// Failed represents count of failed verification,
	// DelayTime represents the end of the disabling password verification process
	//
	// NOTICE: This method will be invoked and run in another goroutine.
	Store(username, Key string, Failed uint, DelayTime time.Time)
}

type TwoFactor struct {
	// Primary strategy that authenticates the user before verifying the one time password.
	// The primary strategy Typically of type basic or LDAP.
	Primary auth.Strategy
	// Cache to store the user session and cache the authentication decision.
	Cache store.Session
	// Resource load and store user two factor data/configuration.
	Resource Resource
	// Header is the name of HTTP request header to extract the user OTP or pin code from it.
	// e.g "x-go-guardian-otp": "662879"
	Header string
	// LockOutStartAt define in what attempt number, lockout mechanism start to work.
	LockOutStartAt uint
	// EnableLockout enable or disable lockout mechanism.
	EnableLockout bool
	// LockOutDelay define delay window to disable password verification process.
	LockOutDelay uint
	// MaxAttempts define max attempts of verification failures to lock the account.
	MaxAttempts uint
}

func (t *TwoFactor) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	const sessionKey = "user-info-session"

	v, ok, err := t.Cache.Load(sessionKey, r)

	if err != nil {
		return nil, err
	}

	if ok {
		info, ok := v.(auth.Info)
		if ok {
			return info, nil
		}
		return nil, gerrors.NewInvalidType((*auth.Info)(nil), info)
	}

	info, err := t.Primary.Authenticate(ctx, r)

	if err != nil {
		return nil, err
	}

	enabled, failed, delay, rawKey := t.Resource.Load(info.UserName())

	if !enabled {
		err = t.Cache.Store(sessionKey, info, r)
		return info, err
	}

	code := r.Header.Get(t.Header)
	if len(code) == 0 {
		return nil, ErrMissingHeader
	}

	key, otp, err := tfa.NewOTPFromKey(rawKey)

	if err != nil {
		return nil, err
	}

	otp.SetFailed(failed)
	otp.SetDelayTime(delay)
	otp.SetMaxAttempts(t.MaxAttempts)
	otp.SetDealy(t.LockOutDelay)
	otp.SetStartAt(t.LockOutStartAt)
	otp.EnableLockout(t.EnableLockout)

	ok, err = otp.Verify(code)

	go t.Resource.Store(info.UserName(), key.String(), otp.Failed(), otp.DelayTime())

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, ErrInvalidOTP
	}

	err = t.Cache.Store(sessionKey, info, r)
	return info, err
}
