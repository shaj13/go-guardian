package bearer

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/auth"
)

func TestAuthenticateMethod(t *testing.T) {
	table := []struct {
		name   string
		header string
	}{
		{
			name:   "it return error when Authorization header missing",
			header: "",
		},
		{
			name:   "it return error when Authorization splited and len less than 2",
			header: "test",
		},
		{
			name:   "it return error when Authorization not holding bearer token type",
			header: "test test",
		},
		{
			name:   "it return error when Authorization holding bearer and token empty",
			header: "Bearer ",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			auth := func(ctx context.Context, r *http.Request, token string) (auth.Info, error) { return nil, nil }
			r, _ := http.NewRequest("GET", "/", nil)
			r.Header.Set("Authorization", tt.header)
			info, err := authenticateFunc(auth).authenticate(r.Context(), r)
			assert.Nil(t, info)
			assert.Error(t, err)
		})
	}
}
