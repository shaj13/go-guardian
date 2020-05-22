package store

import (
	"context"
	"net/http"

	"github.com/gorilla/sessions"
)

// Session implements Cache and provide adaptation to gorilla session store to work with the auth packages.
// Any Store or Delete operation must be followed by invoking SetCookie.
// Otherwise, the result of the caching will be lost.
type Session struct {
	// Name represents session name will be passed to gorilla store
	Name string
	// GStore represents the gorilla session store.
	GStore sessions.Store
}

// Load returns the value stored in the Session for a key, or nil if no value is present.
// The ok result indicates whether value was found in the Session.
// The error returned if an error occurs, Otherwise nil.
func (s *Session) Load(key string, r *http.Request) (interface{}, bool, error) {
	session, err := s.GStore.Get(r, s.Name)
	if err != nil {
		return nil, false, err
	}
	v, ok := session.Values[key]
	return v, ok, nil
}

// Store sets the value for a key.
// The error returned if an error occurs, Otherwise nil.
func (s *Session) Store(key string, value interface{}, r *http.Request) error {
	session, err := s.GStore.Get(r, s.Name)
	if err != nil {
		return err
	}

	session.Values[key] = value
	writer := &cookieRecorder{
		header: make(http.Header),
	}

	err = s.GStore.Save(r, writer, session)
	if err != nil {
		return err
	}

	// r.WithContext() return a shallow copy of r.
	// we must change underlying request so the context value takes effect
	*r = *requestWithCookie(r, writer.Header())
	return nil
}

// Delete the value for a key.
// The error returned if an error occurs, Otherwise nil
func (s *Session) Delete(key string, r *http.Request) error {
	session, err := s.GStore.Get(r, s.Name)
	if err != nil {
		return err
	}

	delete(session.Values, key)
	session.Options.MaxAge = -1
	writer := &cookieRecorder{
		header: make(http.Header),
	}

	err = s.GStore.Save(r, writer, session)
	if err != nil {
		return err
	}

	// r.WithContext() return a shallow copy of r.
	// we must change underlying request so the context value takes effect
	*r = *requestWithCookie(r, writer.Header())
	return nil
}

type cookieRecorder struct {
	header http.Header
}

func (c *cookieRecorder) Header() http.Header       { return c.header }
func (c *cookieRecorder) Write([]byte) (int, error) { return 0, nil }
func (c *cookieRecorder) WriteHeader(int)           {}

type cookieKey struct{}

func requestWithCookie(r *http.Request, h http.Header) *http.Request {
	cookie := h.Get("Set-Cookie")
	ctx := context.WithValue(r.Context(), cookieKey{}, cookie)
	return r.WithContext(ctx)
}

// SetCookie adds a Set-Cookie header to the provided ResponseWriter's header.
// Use this function only when the cache instance of type session.
// Should be invoked before return response back to the end-users.
func SetCookie(w http.ResponseWriter, r *http.Request) {
	if v := r.Context().Value(cookieKey{}); v != nil {
		if cookie, ok := v.(string); ok {
			w.Header().Set("Set-Cookie", cookie)
		}
	}
}
