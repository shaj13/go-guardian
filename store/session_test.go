package store

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
)

func TestSession(t *testing.T) {
	table := []struct {
		name    string
		key     string
		value   interface{}
		op      string
		getErr  bool
		saveErr bool
		found   bool
	}{
		{
			name:   "it return error on Get session when trying to load a value",
			op:     "load",
			getErr: true,
		},
		{
			name:   "it return error Get session when trying to store a value",
			op:     "store",
			getErr: true,
		},
		{
			name:   "it return error Get session when trying to delete a value",
			op:     "store",
			getErr: true,
		},
		{
			name:    "it return error Save session when trying to store a value",
			op:      "store",
			saveErr: true,
		},
		{
			name:    "it return error Save session when trying to delete a value",
			op:      "store",
			saveErr: true,
		},
		{
			name:  "it return false when key does not exist",
			op:    "load",
			key:   "key",
			found: false,
		},
		{
			name: "it return true and value when exist",
			op:   "load",
			// key/value its loaded as default in mock store See L131
			key:   "test",
			value: "test",
			found: true,
		},
		{
			name: "it overwrite exist key and value when store",
			op:   "store",
			// key/value its loaded as default in mock store See L131
			key:   "test",
			value: "test2",
			found: true,
		},
		{
			name: "it create new record when store",
			op:   "store",
			// key/value its loaded as default in mock store See L131
			key:   "key",
			value: "value",
			found: true,
		},
		{
			name: "it's not crash when trying to delete a non exist record",
			op:   "delete",
			// key/value its loaded as default in mock store See L131
			key:   "key",
			found: false,
		},
		{
			name: "it delete a exist record",
			op:   "delete",
			// key/value its loaded as default in mock store See L131
			key:   "test",
			found: false,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockGStore{
				getErr:  tt.getErr,
				saveErr: tt.saveErr,
			}

			sessionCache := &Session{
				GStore: store,
				Name:   "test",
			}

			r, _ := http.NewRequest("GET", "/", nil)
			store.New(r, "")
			var err error

			switch tt.op {
			case "load":
				var v interface{}
				var ok bool
				v, ok, err = sessionCache.Load(tt.key, r)
				assert.Equal(t, tt.value, v)
				assert.Equal(t, tt.found, ok)
			case "store":
				err = sessionCache.Store(tt.key, tt.value, r)
			case "delete":
				err = sessionCache.Delete(tt.key, r)
			}

			if tt.getErr || tt.saveErr {
				assert.True(t, err != nil)
				return
			}

			assert.NoError(t, err)

			// after each op load and assert
			v, ok := store.session.Values[tt.key]
			assert.Equal(t, tt.value, v)
			assert.Equal(t, tt.found, ok)

			// assert cookie eist on request context
			if tt.op != "load" {
				assert.Equal(t, "mockGStore-Cookie", r.Context().Value(cookieKey{}))
			}

		})
	}
}

func TestSetCookie(t *testing.T) {
	table := []struct {
		name     string
		key      interface{}
		value    interface{}
		expected string
	}{
		{
			name: "it not set cookie when cookiekey does not exist in context",
			key:  "sample",
		},
		{
			name:  "it not set cookie when cookiekey value not of type string",
			key:   cookieKey{},
			value: 1,
		},
		{
			name:     "it set cookie when pass all validation",
			key:      cookieKey{},
			value:    "cookie",
			expected: "cookie",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			ctx := context.WithValue(r.Context(), tt.key, tt.value)
			r = r.WithContext(ctx)
			SetCookie(w, r)
			assert.Equal(t, tt.expected, w.Header().Get("Set-Cookie"))
		})
	}
}

type mockGStore struct {
	getErr  bool
	saveErr bool
	session *sessions.Session
}

func (m *mockGStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	if m.getErr {
		return nil, fmt.Errorf("mock GStore error, L32")
	}
	return m.New(r, name)
}

func (m *mockGStore) Save(_ *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	if m.saveErr {
		return fmt.Errorf("mock GStore error, L32")
	}
	w.Header().Set("Set-Cookie", "mockGStore-Cookie")
	m.session = s
	return nil
}

func (m *mockGStore) New(_ *http.Request, _ string) (*sessions.Session, error) {
	m.session = &sessions.Session{
		Values: map[interface{}]interface{}{
			"test": "test",
		},
		Options: &sessions.Options{},
	}
	return m.session, nil
}
