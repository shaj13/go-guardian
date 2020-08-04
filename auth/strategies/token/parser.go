package token

import (
	"net/http"
	"strings"
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
		val := r.Header.Get(header)
		val = strings.TrimSpace(val)

		if val == "" {
			return "", ErrInvalidToken
		}

		return val, nil
	}

	return tokenFn(fn)
}

// AuthorizationParser return a token parser, where token extracted form Authorization header.
func AuthorizationParser(key string) Parser {
	fn := func(r *http.Request) (string, error) {
		header := r.Header.Get("Authorization")
		header = strings.TrimSpace(header)

		if header == "" {
			return "", ErrInvalidToken
		}

		token := strings.Split(header, " ")
		if len(token) < 2 || token[0] != key {
			return "", ErrInvalidToken
		}

		if len(token[1]) == 0 {
			return "", ErrInvalidToken
		}

		return token[1], nil
	}

	return tokenFn(fn)
}

// QueryParser return a token parser, where token extracted form HTTP query string.
func QueryParser(key string) Parser {
	fn := func(r *http.Request) (string, error) {
		query := r.URL.Query()
		token := query.Get(key)
		token = strings.TrimSpace(token)

		if token == "" {
			return "", ErrInvalidToken
		}

		return token, nil
	}

	return tokenFn(fn)
}

// CookieParser return a token parser, where token extracted form HTTP Cookie.
func CookieParser(key string) Parser {
	fn := func(r *http.Request) (string, error) {
		cookie, err := r.Cookie(key)
		if err != nil {
			return "", err
		}

		token := strings.TrimSpace(cookie.Value)

		if token == "" {
			return "", ErrInvalidToken
		}

		return token, nil
	}

	return tokenFn(fn)
}
