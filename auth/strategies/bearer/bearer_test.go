package bearer

import (
	"context"
	"net/http"
	"testing"

	"github.com/shaj13/go-passport/auth"
	"github.com/stretchr/testify/assert"
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

func TestAppend(t *testing.T) {
	table := []struct {
		name        string
		funcName    string
		expectedErr bool
	}{
		{
			funcName:    "append",
			name:        "it return error when strategy, not of type bearer",
			expectedErr: true,
		},
		{
			funcName:    "append",
			name:        "it call append, when strategy valid",
			expectedErr: false,
		},
		{
			funcName:    "revoke",
			name:        "it return error when strategy, not of type bearer",
			expectedErr: true,
		},
		{
			funcName:    "revoke",
			name:        "it call append, when strategy valid",
			expectedErr: false,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			var strat auth.Strategy
			strat = new(mockStrategy)

			if tt.expectedErr {
				strat = new(mockInvalidStrategy)
			}

			var err error
			switch tt.funcName {
			case "append":
				err = Append(strat, "", nil, nil)
			case "revoke":
				err = Revoke(strat, "", nil)
			default:
				t.Errorf("Unsupported function %s", tt.funcName)
				return
			}

			assert.Equal(t, tt.expectedErr, err != nil)

			if !tt.expectedErr {
				assert.True(t, strat.(*mockStrategy).called)
			}
		})
	}
}

type mockStrategy struct {
	called bool
}

func (m *mockStrategy) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	return nil, nil
}
func (m *mockStrategy) append(token string, info auth.Info, r *http.Request) error {
	m.called = true
	return nil
}

func (m *mockStrategy) revoke(token string, r *http.Request) error {
	m.called = true
	return nil
}

type mockInvalidStrategy struct{}

func (m *mockInvalidStrategy) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	return nil, nil
}
