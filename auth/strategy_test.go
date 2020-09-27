package auth

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppendRevoke(t *testing.T) {
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
			var strategy Strategy
			strategy = new(mockStrategy)

			if tt.expectedErr {
				strategy = new(mockInvalidStrategy)
			}

			var err error
			switch tt.funcName {
			case "append":
				err = Append(strategy, "", nil)
			case "revoke":
				err = Revoke(strategy, "")
			default:
				t.Errorf("Unsupported function %s", tt.funcName)
				return
			}

			assert.Equal(t, tt.expectedErr, err != nil)

			if !tt.expectedErr {
				assert.True(t, strategy.(*mockStrategy).called)
			}
		})
	}
}

type mockStrategy struct {
	called    bool
	challenge string
}

func (m *mockStrategy) Authenticate(ctx context.Context, r *http.Request) (Info, error) {
	return nil, nil
}
func (m *mockStrategy) Append(interface{}, Info) error {
	m.called = true
	return nil
}

func (m *mockStrategy) Revoke(interface{}) error {
	m.called = true
	return nil
}

func (m *mockStrategy) Challenge(string) string {
	return m.challenge
}

type mockInvalidStrategy struct{}

func (m *mockInvalidStrategy) Authenticate(ctx context.Context, r *http.Request) (Info, error) {
	return nil, nil
}
