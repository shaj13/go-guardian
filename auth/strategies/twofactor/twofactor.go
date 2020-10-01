// Package twofactor provides authentication strategy,
// to authenticate HTTP requests based on one time password(otp).
package twofactor

import (
	"context"
	"errors"
	"net/http"

	"github.com/shaj13/go-guardian/v2/auth"
)

// ErrInvalidOTP is returned by twofactor strategy,
// When the user-supplied an invalid one time password and verification process failed.
var ErrInvalidOTP = errors.New("strategies/twofactor: Invalid one time password")

// Verifier represents one-time password verification.
type Verifier interface {
	// Verify user one-time password.
	Verify(pin string) (bool, error)
}

// Manager load and store user OTP Verifier.
type Manager interface {
	// Enabled check if two factor for user enabled.
	Enabled(user auth.Info) bool
	// Load return user OTP Verifier or error.
	Load(user auth.Info) (Verifier, error)
	// Store user OTP Verifier.
	Store(user auth.Info, v Verifier) error
}

// TwoFactor represents two factor authentication strategy.
type TwoFactor struct {
	// Primary strategy that authenticates the user before verifying the one time password.
	// The primary strategy Typically of type basic or LDAP.
	Primary auth.Strategy
	Parser  Parser
	Manager Manager
}

// Authenticate returns user info or error by authenticating request using primary strategy,
// and then verifying one-time password.
func (t TwoFactor) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	info, err := t.Primary.Authenticate(ctx, r)
	if err != nil {
		return nil, err
	}

	if !t.Manager.Enabled(info) {
		return info, nil
	}

	pin, err := t.Parser.GetOTP(r)
	if err != nil {
		return nil, err
	}

	otp, err := t.Manager.Load(info)
	if err != nil {
		return nil, err
	}

	defer t.Manager.Store(info, otp)

	ok, err := otp.Verify(pin)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, ErrInvalidOTP
	}

	return info, nil
}
