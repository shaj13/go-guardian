package token

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParser(t *testing.T) {
	table := []struct {
		name    string
		prepare func() (Parser, *http.Request)
		err     error
		token   string
	}{
		{
			name: "XHeaderParser return error when failed to parse token",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				parser := XHeaderParser("X-TOKEN")
				return parser, req
			},
			err:   ErrInvalidToken,
			token: "",
		},
		{
			name: "XHeaderParser return token",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Set("X-API-TOKEN", "api-token")
				parser := XHeaderParser("X-API-TOKEN")
				return parser, req
			},
			err:   nil,
			token: "api-token",
		},
		{
			name: "AuthorizationParser return error when failed to parse token",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				parser := AuthorizationParser("Bearer")
				return parser, req
			},
			err:   ErrInvalidToken,
			token: "",
		},
		{
			name: "AuthorizationParser return error when failed to parse token -- key missing",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Set("Authorization", "token")
				parser := AuthorizationParser("Bearer")
				return parser, req
			},
			err:   ErrInvalidToken,
			token: "",
		},
		{
			name: "AuthorizationParser return token",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Set("Authorization", "Bearer token")
				parser := AuthorizationParser("Bearer")
				return parser, req
			},
			err:   nil,
			token: "token",
		},
		{
			name: "QueryParser return error when failed to parse token",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				parser := QueryParser("api_key")
				return parser, req
			},
			err:   ErrInvalidToken,
			token: "",
		},
		{
			name: "QueryParser return token",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/something?api_key=abcdef12345", nil)
				parser := QueryParser("api_key")
				return parser, req
			},
			err:   nil,
			token: "abcdef12345",
		},
		{
			name: "CookieParser return error when failed to find Cookie",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				parser := CookieParser("api_key")
				return parser, req
			},
			err:   http.ErrNoCookie,
			token: "",
		},
		{
			name: "CookieParser return error when failed to parse token",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				cookie := &http.Cookie{Name: "api_key", Value: ""}
				req.AddCookie(cookie)
				parser := CookieParser("api_key")
				return parser, req
			},
			err:   ErrInvalidToken,
			token: "",
		},
		{
			name: "CookieParser return error when failed to parse token",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				cookie := &http.Cookie{Name: "api_key", Value: "cookieToken"}
				req.AddCookie(cookie)
				parser := CookieParser("api_key")
				return parser, req
			},
			err:   nil,
			token: "cookieToken",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			p, r := tt.prepare()
			token, err := p.Token(r)

			assert.Equal(t, tt.token, token)
			assert.Equal(t, tt.err, err)
		})
	}
}
