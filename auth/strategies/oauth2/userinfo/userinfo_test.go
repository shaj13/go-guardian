//nolint:lll
package userinfo

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/m87carlson/go-guardian/v2/auth/strategies/oauth2"
)

func TestUserInfo(t *testing.T) {
	table := []struct {
		name         string
		body         string
		header       string
		contains     string
		code         int
		expectedInfo bool
	}{
		{
			name:     "it return error when server return error at body",
			body:     "error_invalid_request",
			contains: "invalid_request",
			code:     400,
		},
		{
			name:     "it return error when server return invalid response json",
			body:     "invalid_json",
			contains: "Failed to unmarshal",
			code:     200,
		},
		{
			name:     "it return error when server return error at header",
			header:   "header_invalid_token",
			contains: "invalid_token",
			code:     401,
		},
		{
			name:     "it return an error when server repond without any body and header",
			contains: "Authorization server",
			code:     401,
		},
		{
			name:         "it return user info",
			code:         200,
			body:         "user_info",
			expectedInfo: true,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			srv := mockAuthzServer(t, tt.body, tt.header, tt.code)
			fn := GetAuthenticateFunc(srv.URL)
			info, _, err := fn(context.TODO(), nil, "token")

			if len(tt.contains) > 0 {
				assert.Contains(t, err.Error(), tt.contains)
			}

			assert.Equal(t, tt.expectedInfo, info != nil)
		})
	}
}

func TestErrorFromHeader(t *testing.T) {

	table := []struct {
		name     string
		header   string
		contains string
	}{
		{
			name:     "it parse header without Bearer",
			header:   string(readFile(t, "header_invalid_token")),
			contains: "invalid_token",
		},
		{
			name:     "it parse header with additional info",
			header:   string(readFile(t, "header_invalid_request")),
			contains: "invalid_request",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			h.Set(wwwauth, tt.header)
			err := errorFromHeader(h, &oauth2.ResponseError{})
			assert.Contains(t, err.Error(), tt.contains)
		})
	}
}

func BenchmarkUserinfo(b *testing.B) {
	r, _ := http.NewRequest("GET", "/", nil)
	srv := mockAuthzServer(b, "user_info", "", 200)
	fn := GetAuthenticateFunc(srv.URL)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := fn(context.TODO(), r, "token")
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func mockAuthzServer(tb testing.TB, bodyFile, headerFile string, code int) *httptest.Server {
	body := readFile(tb, bodyFile)
	header := readFile(tb, headerFile)

	h := func(w http.ResponseWriter, r *http.Request) {
		if len(header) > 0 {
			w.Header().Set("WWW-Authenticate", string(header))
		}

		w.WriteHeader(code)

		if len(body) > 0 {
			w.Write(body)
		}
	}

	return httptest.NewServer(http.HandlerFunc(h))
}

func readFile(tb testing.TB, filename string) []byte {
	if len(filename) == 0 {
		return nil
	}

	body, err := ioutil.ReadFile("./testdata/" + filename)
	if err != nil {
		tb.Fatalf("Failed to read testdata file Err: %s", err)
	}

	return body
}
