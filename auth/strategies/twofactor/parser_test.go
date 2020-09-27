package twofactor

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParser(t *testing.T) {
	table := []struct {
		name    string
		prepare func() (Parser, *http.Request)
		err     error
		pin     string
	}{
		{
			name: "XHeaderParser return error when failed to parse pin",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				parser := XHeaderParser("X-OTP")
				return parser, req
			},
			err: ErrMissingOTP,
			pin: "",
		},
		{
			name: "XHeaderParser return pin",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Set("X-OTP", "123456")
				parser := XHeaderParser("X-OTP")
				return parser, req
			},
			err: nil,
			pin: "123456",
		},
		{
			name: "QueryParser return error when failed to parse pin",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				parser := QueryParser("otp")
				return parser, req
			},
			err: ErrMissingOTP,
			pin: "",
		},
		{
			name: "QueryParser return pin",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/something?otp=123456", nil)
				parser := QueryParser("otp")
				return parser, req
			},
			err: nil,
			pin: "123456",
		},
		{
			name: "CookieParser return error when failed to find Cookie",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				parser := CookieParser("otp")
				return parser, req
			},
			err: http.ErrNoCookie,
			pin: "",
		},
		{
			name: "CookieParser return error when failed to parse pin",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				cookie := &http.Cookie{Name: "otp", Value: ""}
				req.AddCookie(cookie)
				parser := CookieParser("otp")
				return parser, req
			},
			err: ErrMissingOTP,
			pin: "",
		},
		{
			name: "CookieParser return error when failed to parse pin",
			prepare: func() (Parser, *http.Request) {
				req, _ := http.NewRequest("GET", "/", nil)
				cookie := &http.Cookie{Name: "otp", Value: "123456"}
				req.AddCookie(cookie)
				parser := CookieParser("otp")
				return parser, req
			},
			err: nil,
			pin: "123456",
		},
		{
			name: "JSONBodyParser return otp",
			prepare: func() (Parser, *http.Request) {
				reader := strings.NewReader(`{"otp":"123456"}`)
				req, _ := http.NewRequest("GET", "/", reader)
				parser := JSONBodyParser("otp")
				return parser, req
			},
			pin: "123456",
		},
		{
			name: "JSONBodyParser return error when otp missing",
			prepare: func() (Parser, *http.Request) {
				reader := strings.NewReader(`{"pin":"123456"}`)
				req, _ := http.NewRequest("GET", "/", reader)
				parser := JSONBodyParser("otp")
				return parser, req
			},
			err: ErrMissingOTP,
			pin: "",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			p, r := tt.prepare()
			pin, err := p.GetOTP(r)

			assert.Equal(t, tt.pin, pin)
			assert.Equal(t, tt.err, err)
		})
	}
}
