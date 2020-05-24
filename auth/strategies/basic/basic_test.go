package basic

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/shaj13/go-guardian/auth"
)

//nolint:goconst
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
			info, err := AuthenticateFunc(auth).Authenticate(r.Context(), r)

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

//nolint:goconst
func TestNewCached(t *testing.T) {
	authFunc := func(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error) {
		if userName == "auth-error" {
			return nil, fmt.Errorf("Invalid credentials")
		}

		return auth.NewDefaultUser("test", "10", nil, nil), nil
	}

	table := []struct {
		name           string
		setCredentials func(r *http.Request)
		expectedErr    bool
	}{
		{
			name:           "it return user from cache",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("predefined2", "test") },
			expectedErr:    false,
		},
		{
			name:           "it re-authenticate user when hash missing",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("predefined3", "test") },
			expectedErr:    false,
		},
		{
			name:           "it return error when cache hold invalid user info",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("predefined", "test") },
			expectedErr:    true,
		},
		{
			name:           "it return error when cache return error on load",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("error", "test") },
			expectedErr:    true,
		},
		{
			name:           "it return error when cache return error on store",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("store-error", "test") },
			expectedErr:    true,
		},
		{
			name:           "it return user info when request authenticated",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("test", "test") },
			expectedErr:    false,
		},
		{
			name:           "it return error when request has invalid credentials",
			setCredentials: func(r *http.Request) { r.SetBasicAuth("auth-error", "unknown") },
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

			cache := make(mockCache)
			cache["predefined"] = "invalid-type"
			cache["predefined2"] = auth.NewDefaultUser(
				"predefined2",
				"10",
				nil,
				map[string][]string{
					ExtensionKey: {"$2a$10$aj7RBUkAjknXMyqeLW0v3.FF0aarP4/MraQD7bsmvQ6YSQzxCyyKG"},
				},
			)
			cache["predefined3"] = auth.NewDefaultUser("predefined3", "10", nil, nil)

			info, err := New(authFunc, cache).Authenticate(r.Context(), r)

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

type mockCache map[string]interface{}

func (m mockCache) Load(key string, _ *http.Request) (interface{}, bool, error) {
	if key == "error" {
		return nil, false, fmt.Errorf("Load Error")
	}
	v, ok := m[key]
	return v, ok, nil
}

func (m mockCache) Store(key string, value interface{}, _ *http.Request) error {
	if key == "store-error" {
		return fmt.Errorf("Store Error")
	}
	m[key] = value
	return nil
}

func (m mockCache) Delete(key string, _ *http.Request) error {
	return nil
}
