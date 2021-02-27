package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestLdap(t *testing.T) {
	table := []struct {
		name        string
		expectedErr bool
		cfg         *Config
		user        string
		id          string
		prepare     func(m *mockConn)
	}{
		{
			name:        "it return error when dial return error",
			expectedErr: true,
			prepare: func(m *mockConn) {
				m.On("mockDial").Return(nil, fmt.Errorf("mockDial error"))
			},
		},
		{
			name:        "it return error when Bind return error",
			expectedErr: true,
			cfg: &Config{
				BindPassword: "readonly",
			},
			prepare: func(m *mockConn) {
				m.On("mockDial").Return(nil, nil)
				m.On("Bind").Return(fmt.Errorf("Bind error"))
			},
		},
		{
			name:        "it return error when UnauthenticatedBind return error",
			expectedErr: true,
			cfg:         &Config{},
			prepare: func(m *mockConn) {
				m.On("mockDial").Return(nil, nil)
				m.On("UnauthenticatedBind").Return(fmt.Errorf("UnauthenticatedBind error"))
			},
		},
		{
			name:        "it return error when Search return error",
			expectedErr: true,
			cfg: &Config{
				BindPassword: "readonly",
			},
			prepare: func(m *mockConn) {
				m.On("mockDial").Return(nil, nil)
				m.On("Bind").Return(nil)
				m.On("Search").Return(new(ldap.SearchResult), fmt.Errorf("Search error"))
			},
		},
		{
			name:        "it return error when Search 0 entries",
			expectedErr: true,
			cfg: &Config{
				BindPassword: "readonly",
			},
			prepare: func(m *mockConn) {
				m.On("mockDial").Return(nil, nil)
				m.On("Bind").Return(nil)
				m.On("Search").Return(new(ldap.SearchResult), nil)
			},
		},
		{
			name:        "it return error when Bind userDN (ldap.go L110) return error",
			expectedErr: true,
			cfg:         &Config{},
			prepare: func(m *mockConn) {
				m.On("mockDial").Return(nil, nil)
				m.On("UnauthenticatedBind").Return(nil)
				m.On("Bind").Return(fmt.Errorf("Bind error"))

				entry := &ldap.Entry{
					DN: "test",
				}
				result := &ldap.SearchResult{
					Entries: []*ldap.Entry{
						entry,
					},
				}
				m.On("Search").Return(result, nil)
			},
		},
		{
			name:        "it return user when successfully authenticated",
			expectedErr: false,
			cfg:         &Config{},
			id:          "1",
			user:        "test",
			prepare: func(m *mockConn) {
				m.On("mockDial").Return(nil, nil)
				m.On("Bind").Return(nil)
				m.On("UnauthenticatedBind").Return(nil)

				entry := &ldap.Entry{
					DN: "test",
					Attributes: []*ldap.EntryAttribute{
						ldap.NewEntryAttribute("uid", []string{"1"}),
					},
				}
				result := &ldap.SearchResult{
					Entries: []*ldap.Entry{
						entry,
					},
				}
				m.On("Search").Return(result, nil)
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			m := &mockConn{
				Mock: mock.Mock{},
			}

			tt.prepare(m)

			c := client{
				cfg:  tt.cfg,
				dial: m.mockDial,
			}

			info, err := c.authenticate(context.Background(), nil, tt.user, "")

			assert.Equal(t, tt.expectedErr, err != nil)

			if !tt.expectedErr {
				assert.Equal(t, tt.id, info.GetID())
				assert.Equal(t, tt.user, info.GetUserName())
			}
		})
	}

}

func TestDial(t *testing.T) {
	table := []struct {
		newServer func(http.Handler) *httptest.Server
		expectTLS bool
	}{
		{
			newServer: httptest.NewServer,
			expectTLS: false,
		},
		{
			newServer: httptest.NewTLSServer,
			expectTLS: true,
		},
	}

	for _, tt := range table {
		ts := tt.newServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		defer ts.Close()
		if tt.expectTLS {
			ts.TLS.InsecureSkipVerify = true
		}
		u, _ := url.Parse(ts.URL)
		cfg := Config{
			Port: u.Port(),
			Host: u.Hostname(),
			TLS:  ts.TLS,
		}

		c, err := dial(&cfg)
		if assert.NoError(t, err) {
			_, isTLS := c.(*ldap.Conn).TLSConnectionState()
			assert.Equal(t, tt.expectTLS, isTLS)
		}
	}
}

type mockConn struct {
	mock.Mock
}

func (m *mockConn) mockDial(cfg *Config) (conn, error) {
	args := m.Called()
	return m, args.Error(1)
}
func (m *mockConn) Bind(username, password string) error {
	args := m.Called()
	return args.Error(0)
}
func (m *mockConn) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	args := m.Called()
	return args.Get(0).(*ldap.SearchResult), args.Error(1)
}
func (m *mockConn) StartTLS(config *tls.Config) error {
	args := m.Called()
	return args.Error(0)
}
func (m *mockConn) UnauthenticatedBind(username string) error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockConn) Close() {}
