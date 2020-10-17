//nolint: lll
package kubernetes

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/auth"
)

func TestNewKubeReview(t *testing.T) {
	// Round #1 -- check default
	kr := newKubeReview()
	assert.NotNil(t, kr.client)
	assert.NotNil(t, kr.client.Transport)
	assert.Equal(t, kr.apiVersion, "authentication.k8s.io/v1")
	assert.Equal(t, kr.addr, "http://127.0.0.1:6443")

	// Round #2 -- apply opt and trim "/"
	ver := SetAPIVersion("/test/v1/")
	addr := SetAddress("http://127.0.0.1:8080/")
	kr = newKubeReview(ver, addr)
	assert.Equal(t, kr.apiVersion, "test/v1")
	assert.Equal(t, kr.addr, "http://127.0.0.1:8080")
}

func TestKubeReview(t *testing.T) {
	table := []struct {
		name string
		code int
		file string
		err  error
		info auth.Info
	}{
		{
			name: "it return error when server return error status",
			code: 200,
			file: "error_meta_status",
			err:  fmt.Errorf("strategies/kubernetes: Kube API Error"),
		},
		{
			name: "it return error when server return invalid token review",
			code: 200,
			file: "invalid_token_review",
			err:  fmt.Errorf(`strategies/kubernetes: Failed to Unmarshal Response body to TokenReview Err: invalid character 'i' looking for beginning of value`),
		},
		{
			name: "it return error when server return Status.Error",
			code: 200,
			file: "error_token_review",
			err:  fmt.Errorf("strategies/kubernetes: Failed to authenticate token"),
		},
		{
			name: "it return error when server return Status.Authenticated false",
			code: 200,
			file: "unauthorized_token_review",
			err:  fmt.Errorf("strategies/kubernetes: Token Unauthorized"),
		},
		{
			name: "it return user info",
			code: 200,
			file: "user_token_review",
			info: auth.NewUserInfo("test", "1", nil, map[string][]string{"ext": {"1"}}),
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			srv := mockKubeAPIServer(t, tt.file, tt.code)
			kr := &kubeReview{
				addr:   srv.URL,
				client: srv.Client(),
			}
			r, _ := http.NewRequest("", "", nil)
			info, _, err := kr.authenticate(r.Context(), r, "")

			assert.Equal(t, tt.err, err)
			assert.Equal(t, tt.info, info)
		})
	}
}

func mockKubeAPIServer(tb testing.TB, file string, code int) *httptest.Server {
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
