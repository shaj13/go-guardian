package basic

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/shaj13/go-passport/auth"
)

func Test(t *testing.T) {
	auth := func(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error) {
		if userName == "test" && password == "test" {
			return auth.NewDefaultUser("test", "10", nil, nil), nil
		}

		return nil, fmt.Errorf("Invalid credentials")
	}

	table := []struct {
		name           string
		setCredentials func(r *http.Request)
		expectedErr    bool
	}{
		{
			name:           "it return user info when request authenticated",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("test", "test") },
			expectedErr:    false,
		},
		{
			name:           "it return error when request has invalid credentials",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("unknown", "unknown") },
			expectedErr:    true,
		},
		{
			name:           "it return error when request missing basic auth params",
			setCredentials: func(r *http.Request) { /* no op */ },
			expectedErr:    true,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			tt.setCredentials(r)
			info, err := Authenticate(auth).Authenticate(r.Context(), r)

			if tt.expectedErr && err == nil {
				t.Errorf("%s: Expected error, got none", tt.name)
				return
			}

			if !tt.expectedErr && info == nil {
				t.Errorf("%s: Expected info object, got nil: %v", tt.name, err)
				return
			}
		})
	}
}
