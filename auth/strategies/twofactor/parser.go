package twofactor

import (
	"errors"
	"net/http"

	"github.com/shaj13/go-guardian/v2/auth/internal"
)

// ErrMissingOTP is returned by Parser,
// When one-time password missing or empty in HTTP request.
var ErrMissingOTP = errors.New("strategies/twofactor: One-time password missing or empty")

// Parser parse and extract one-time password from incoming HTTP request.
type Parser interface {
	GetOTP(r *http.Request) (string, error)
}

type otpFn func(r *http.Request) (string, error)

func (fn otpFn) GetOTP(r *http.Request) (string, error) {
	return fn(r)
}

// XHeaderParser return a one-time password parser, where otp extracted form "X-" header.
func XHeaderParser(header string) Parser {
	fn := func(r *http.Request) (string, error) {
		return internal.ParseHeader(header, r, ErrMissingOTP)
	}

	return otpFn(fn)
}

// JSONBodyParser return a one-time password parser, where otp extracted form request body.
func JSONBodyParser(key string) Parser {
	fn := func(r *http.Request) (string, error) {
		return internal.ParseJSONBody(key, r, ErrMissingOTP)
	}

	return otpFn(fn)
}

// QueryParser return a one-time password parser, where otp extracted form HTTP query string.
func QueryParser(key string) Parser {
	fn := func(r *http.Request) (string, error) {
		return internal.ParseQuery(key, r, ErrMissingOTP)
	}

	return otpFn(fn)
}

// CookieParser return a one-time password parser, where otp extracted form HTTP Cookie.
func CookieParser(key string) Parser {
	fn := func(r *http.Request) (string, error) {
		return internal.ParseCookie(key, r, ErrMissingOTP)
	}

	return otpFn(fn)
}
