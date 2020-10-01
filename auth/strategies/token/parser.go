package token

import (
	"net/http"

	"github.com/shaj13/go-guardian/v2/auth/internal"
)

// Parser parse and extract token from incoming HTTP request.
type Parser interface {
	Token(r *http.Request) (string, error)
}

type tokenFn func(r *http.Request) (string, error)

func (fn tokenFn) Token(r *http.Request) (string, error) {
	return fn(r)
}

// XHeaderParser return a token parser, where token extracted form "X-" header.
func XHeaderParser(header string) Parser {
	fn := func(r *http.Request) (string, error) {
		return internal.ParseHeader(header, r, ErrInvalidToken)
	}

	return tokenFn(fn)
}

// AuthorizationParser return a token parser, where token extracted form Authorization header.
func AuthorizationParser(key string) Parser {
	fn := func(r *http.Request) (string, error) {
		return internal.ParseAuthorizationHeader(key, r, ErrInvalidToken)
	}

	return tokenFn(fn)
}

// QueryParser return a token parser, where token extracted form HTTP query string.
func QueryParser(key string) Parser {
	fn := func(r *http.Request) (string, error) {
		return internal.ParseQuery(key, r, ErrInvalidToken)
	}

	return tokenFn(fn)
}

// CookieParser return a token parser, where token extracted form HTTP Cookie.
func CookieParser(key string) Parser {
	fn := func(r *http.Request) (string, error) {
		return internal.ParseCookie(key, r, ErrInvalidToken)
	}

	return tokenFn(fn)
}

// JSONBodyParser return a token parser, where token extracted extracted form request body.
func JSONBodyParser(key string) Parser {
	fn := func(r *http.Request) (string, error) {
		return internal.ParseJSONBody(key, r, ErrInvalidToken)
	}

	return tokenFn(fn)
}
