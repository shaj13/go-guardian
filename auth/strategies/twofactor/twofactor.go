package twofactor

import (
	"context"
	"errors"
	"net/http"

	"github.com/shaj13/go-guardian/auth"
)

// StrategyKey export identifier for the two factor strategy,
// commonly used when enable/add strategy to go-guardian authenticator.
const StrategyKey = auth.StrategyKey("2FA.Strategy")

// ErrInvalidPin is returned by strategy,
// When the user-supplied an invalid one time password and verification process failed.
var ErrInvalidPin = errors.New("strategies/twofactor: Invalid one time password")

// OTP represents one-time password verification.
type OTP interface {
	// Verify user one-time password.
	Verify(pin string) (bool, error)
}

// OTPManager load and store user OTP.
type OTPManager interface {
	// Enabled check if two factor for user enabled.
	Enabled(user auth.Info) bool
	// Load return user OTP or error.
	Load(user auth.Info) (OTP, error)
	// Store user OTP.
	Store(user auth.Info, otp OTP) error
}

// Strategy represents two factor authentication strategy.
type Strategy struct {
	// Primary strategy that authenticates the user before verifying the one time password.
	// The primary strategy Typically of type basic or LDAP.
	Primary auth.Strategy
	Parser  Parser
	Manager OTPManager
}

// Authenticate returns user info or error by authenticating request using primary strategy,
// and then verifying one-time password.
func (s Strategy) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	info, err := s.Primary.Authenticate(ctx, r)
	if err != nil {
		return nil, err
	}

	if !s.Manager.Enabled(info) {
		return info, nil
	}

	pin, err := s.Parser.PinCode(r)
	if err != nil {
		return nil, err
	}

	otp, err := s.Manager.Load(info)
	if err != nil {
		return nil, err
	}

	defer s.Manager.Store(info, otp)

	ok, err := otp.Verify(pin)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, ErrInvalidPin
	}

	return info, nil
}
