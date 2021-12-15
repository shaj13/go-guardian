package token

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/m87carlson/go-guardian/v2/auth"
)

func TestWithGetScope(t *testing.T) {
	table := []struct {
		name            string
		scopes          []string
		info            auth.Info
		anExistExtKey   string
		anExistExtValue string
	}{
		{
			name:   "it add/get scopes when info ext is nil",
			scopes: []string{"test.read", "test.write"},
			info:   auth.NewUserInfo("test", "test", nil, nil),
		},
		{
			name:            "it add/get scopes from when info ext is not nil and does not change other extensions",
			scopes:          []string{"test.read", "test.write"},
			info:            auth.NewUserInfo("test", "test", nil, auth.Extensions{"key": []string{"value"}}),
			anExistExtKey:   "key",
			anExistExtValue: "value",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			WithNamedScopes(tt.info, tt.scopes...)
			scopes := GetNamedScopes(tt.info)
			assert.Equal(t, tt.scopes, scopes)
			assert.Equal(t, tt.anExistExtValue, tt.info.GetExtensions().Get(tt.anExistExtKey))
		})
	}
}

func TestScopeVerify(t *testing.T) {
	table := []struct {
		name     string
		scope    Scope
		path     string
		method   string
		expected bool
	}{
		{
			name:     "Verify should pass when endpiont and method empty",
			scope:    NewScope("test", "", ""),
			path:     "/test",
			method:   http.MethodGet,
			expected: true,
		},
		{
			name:     "Verify should pass when endpiont empty and method equal request method",
			scope:    NewScope("test", "", http.MethodGet),
			path:     "/test",
			method:   http.MethodGet,
			expected: true,
		},
		{
			name:     "Verify should not pass when endpiont empty and method not equal request method",
			scope:    NewScope("test", "", http.MethodDelete),
			path:     "/test",
			method:   http.MethodGet,
			expected: false,
		},
		{
			name:     "Verify should pass when method empty and endpoint substr of request path",
			scope:    NewScope("test", "/test", ""),
			path:     "/test",
			method:   http.MethodGet,
			expected: true,
		},
		{
			name:     "Verify should not pass when method empty and endpoint not substr of request path",
			scope:    NewScope("test", "/test.2", ""),
			path:     "/test",
			method:   http.MethodGet,
			expected: false,
		},
		{
			name:     "Verify should pass when method equal request method and endpoint substr of request path",
			scope:    NewScope("test", "/test", http.MethodGet),
			path:     "/test",
			method:   http.MethodGet,
			expected: true,
		},
		{
			name:     "Verify should not pass when method not equal request method and endpoint not substr of request path",
			scope:    NewScope("test", "/test.2", http.MethodDelete),
			path:     "/test",
			method:   http.MethodGet,
			expected: false,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest(tt.method, tt.path, nil)
			ok := tt.scope.Verify(r.Context(), r, nil, "")
			assert.Equal(t, tt.expected, ok)
		})
	}
}

func TestVerifyScopes(t *testing.T) {
	const (
		path       = "/test"
		method     = http.MethodGet
		namedScope = "test.read"
	)

	table := []struct {
		name       string
		namedScope string
		scope      Scope
		err        error
	}{
		{
			name:  "it return nil error when user does not have scope",
			scope: NewScope(namedScope, path, method),
		},
		{
			name:       "it return nil error when user scope match request",
			scope:      NewScope(namedScope, path, method),
			namedScope: namedScope,
		},
		{
			name:       "it return error when user scope does not match request",
			scope:      NewScope(namedScope, path, method),
			namedScope: "does-not-exist",
			err:        ErrTokenScopes,
		},
		{
			name:       "it return error when user scope does not exist",
			scope:      NewScope(namedScope, "/test.2", method),
			namedScope: namedScope,
			err:        ErrTokenScopes,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest(method, path, nil)
			info := auth.NewUserInfo("TestVerifyScopes", "TestVerifyScopes", nil, nil)

			if len(tt.namedScope) == 0 {
				WithNamedScopes(info)
			} else {
				WithNamedScopes(info, tt.namedScope)
			}

			err := verifyScopes(tt.scope)(r.Context(), r, info, "")
			assert.Equal(t, tt.err, err)
		})
	}
}
