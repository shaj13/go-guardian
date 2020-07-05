package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
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
				err = Append(strategy, "", nil, nil)
			case "revoke":
				err = Revoke(strategy, "", nil)
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

func TestSetWWWAuthenticate(t *testing.T) {
	var (
		basic   = &mockStrategy{challenge: `Basic realm="test"`}
		bearer  = &mockStrategy{challenge: `Bearer realm="test"`}
		invalid = new(mockInvalidStrategy)
	)

	table := []struct {
		name       string
		strategies []Strategy
		expected   string
	}{
		{
			name:     "it does not set heder when no provided strategies",
			expected: "",
		},
		{
			name:       "it does not set heder when no provided strategies not implements Challenge method",
			strategies: []Strategy{invalid},
			expected:   "",
		},
		{
			name:       "it ignore strategy if not implements Challenge method",
			strategies: []Strategy{basic, invalid},
			expected:   `Basic realm="test"`,
		},
		{
			name:       "it consolidate strategies challenges into header",
			strategies: []Strategy{basic, bearer},
			expected:   `Basic realm="test", Bearer realm="test"`,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			SetWWWAuthenticate(w, "test", tt.strategies...)

			got := w.Header().Get("WWW-Authenticate")

			assert.Equal(t, tt.expected, got)
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
func (m *mockStrategy) Append(token string, info Info, r *http.Request) error {
	m.called = true
	return nil
}

func (m *mockStrategy) Revoke(token string, r *http.Request) error {
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
