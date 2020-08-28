package twofactor

import (
	"errors"
	"net/http"

	"github.com/shaj13/go-guardian/internal"
)

// ErrMissingPin is returned by Parser,
// When one-time password missing or empty in HTTP request.
var ErrMissingPin = errors.New("strategies/twofactor: One-time password missing or empty")

// Parser parse and extract one-time password from incoming HTTP request.
type Parser interface {
	PinCode(r *http.Request) (string, error)
}

type pinFn func(r *http.Request) (string, error)

func (fn pinFn) PinCode(r *http.Request) (string, error) {
	return fn(r)
}

// XHeaderParser return a one-time password parser, where pin extracted form "X-" header.
func XHeaderParser(header string) Parser {
	fn := func(r *http.Request) (string, error) {
		return internal.ParseHeader(header, r, ErrMissingPin)
	}

	return pinFn(fn)
}

// JSONBodyParser return a one-time password parser, where pin extracted form request body.
func JSONBodyParser(key string) Parser {
	fn := func(r *http.Request) (string, error) {
		return internal.ParseJSONBody(key, r, ErrMissingPin)
	}

	return pinFn(fn)
}

// QueryParser return a one-time password parser, where pin extracted form HTTP query string.
func QueryParser(key string) Parser {
	fn := func(r *http.Request) (string, error) {
		return internal.ParseQuery(key, r, ErrMissingPin)
	}

	return pinFn(fn)
}

// CookieParser return a one-time password parser, where pin extracted form HTTP Cookie.
func CookieParser(key string) Parser {
	fn := func(r *http.Request) (string, error) {
		return internal.ParseCookie(key, r, ErrMissingPin)
	}

	return pinFn(fn)
}
