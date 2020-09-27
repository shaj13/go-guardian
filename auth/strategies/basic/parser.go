package basic

import "net/http"

// Parser parse and extract user credentials from incoming HTTP request.
type Parser interface {
	Credentials(r *http.Request) (string, string, error)
}

type credentialsFn func(r *http.Request) (string, string, error)

func (fn credentialsFn) Credentials(r *http.Request) (string, string, error) {
	return fn(r)
}

// AuthorizationParser return a credentials parser,
// where credentials extracted form Authorization header.
func AuthorizationParser() Parser {
	fn := func(r *http.Request) (string, string, error) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			return "", "", ErrMissingPrams
		}
		return user, pass, nil
	}

	return credentialsFn(fn)
}
