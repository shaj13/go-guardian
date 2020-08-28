// Package internal contains support & helpers for go-guardian packages.
package internal

import (
	"net/http"
	"strings"
)

//ParseHeader extract specific header value or return provided error.
func ParseHeader(header string, r *http.Request, err error) (string, error) {
	value := r.Header.Get(header)
	value = strings.TrimSpace(value)

	if value == "" {
		return "", err
	}

	return value, nil
}

//ParseAuthorizationHeader extract Authorization header value or return provided error.
func ParseAuthorizationHeader(key string, r *http.Request, err error) (string, error) {
	header := r.Header.Get("Authorization")
	header = strings.TrimSpace(header)

	if header == "" {
		return "", err
	}

	value := strings.Split(header, " ")
	if len(value) < 2 || value[0] != key {
		return "", err
	}

	if len(value[1]) == 0 {
		return "", err
	}

	return value[1], nil
}

//ParseQuery extract key value form HTTP query string  or return provided error.
func ParseQuery(key string, r *http.Request, err error) (string, error) {
	query := r.URL.Query()
	value := query.Get(key)
	value = strings.TrimSpace(value)

	if value == "" {
		return "", err
	}

	return value, nil
}

//ParseCookie extract key value form form HTTP Cookie or return provided error.
func ParseCookie(key string, r *http.Request, e error) (string, error) {
	cookie, err := r.Cookie(key)
	if err != nil {
		return "", err
	}

	value := strings.TrimSpace(cookie.Value)

	if value == "" {
		return "", e
	}

	return value, nil
}
