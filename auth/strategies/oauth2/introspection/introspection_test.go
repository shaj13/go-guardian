//nolint:lll
package introspection

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntrospection(t *testing.T) {
	table := []struct {
		name         string
		code         int
		file         string
		err          error
		expectedInfo bool
	}{
		{
			name: "it return error when server return error status",
			code: 400,
			file: "error_status",
			err:  fmt.Errorf("strategies/oauth2/introspection: strategies/oauth2: invalid_request, the post body can not be empty"),
		},
		{
			name: "it return error when server return invalid token introspection json",
			code: 200,
			file: "invalid_token_introspection",
			err:  fmt.Errorf(`strategies/oauth2/introspection: Failed to unmarshal response body data, Type: *introspection.claimsResponse Err: invalid character 'i' looking for beginning of value`),
		},
		{
			name: "it return error when server return active false",
			code: 200,
			file: "unauthorized_token",
			err:  fmt.Errorf("strategies/oauth2/introspection: Token Unauthorized"),
		},
		{
			name:         "it return user info",
			code:         200,
			file:         "user_token",
			expectedInfo: true,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			srv := mockAuthzServer(t, tt.file, tt.code)
			fn := GetAuthenticateFunc(srv.URL)
			info, _, err := fn(context.TODO(), nil, "token")

			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			}

			assert.Equal(t, tt.expectedInfo, info != nil)
		})
	}
}

func BenchmarkIntrospection(b *testing.B) {
	r, _ := http.NewRequest("GET", "/", nil)
	srv := mockAuthzServer(b, "user_token", 200)
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

func mockAuthzServer(tb testing.TB, file string, code int) *httptest.Server {
	body, err := ioutil.ReadFile("./testdata/" + file)

	if err != nil {
		tb.Fatalf("Failed to read testdata file Err: %s", err)
	}

	h := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		w.Write(body)
	}

	return httptest.NewServer(http.HandlerFunc(h))
}
