// Package ldap provides authentication strategy,
// to authenticate HTTP requests and builds, extracts user informations from LDAP Server.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/shaj13/go-guardian/auth"
	"github.com/shaj13/go-guardian/auth/strategies/basic"
	"github.com/shaj13/go-guardian/store"

	"gopkg.in/ldap.v3"
)

// ErrEntries is returned by ldap authenticate function,
// When search result return user DN does not exist or too many entries returned.
var ErrEntries = errors.New("LDAP: Serach user DN does not exist or too many entries returned")

type conn interface {
	Bind(username, password string) error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	StartTLS(config *tls.Config) error
	UnauthenticatedBind(username string) error
	Close()
}

// Config define the configuration to connect to LDAP.
type Config struct {
	// Port LDAP server port.
	Port string
	// Host LDAP server host.
	Host string
	// TLS configuration, if nil connect without TLS.
	TLS *tls.Config
	// BindDN represents LDAP DN for searching for the user DN.
	// Typically read only user DN.
	BindDN string
	// BindPassword LDAP password for searching for the user DN.
	// Typically read only user password.
	BindPassword string
	// Attributes used for users.
	Attributes []string
	// BaseDN LDAP domain to use for users.
	BaseDN string
	// Filter for the User Object Filter.
	// if username nedded more than once use fmt index pattern (%[1]s).
	// Otherwise %s.
	Filter string
}

func dial(cfg *Config) (conn, error) {
	scheme := "ldap"

	if cfg.TLS != nil {
		scheme = "ldaps"
	}
	addr := fmt.Sprintf("%s://%s:%s", scheme, cfg.Host, cfg.Port)
	return ldap.DialURL(addr)
}

type client struct {
	dial func(cfg *Config) (conn, error)
	cfg  *Config
}

func (c client) authenticate(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error) { //nolint:lll
	l, err := c.dial(c.cfg)

	if err != nil {
		return nil, err
	}

	defer l.Close()

	if c.cfg.TLS != nil {
		err = l.StartTLS(c.cfg.TLS)
	}

	if err != nil {
		return nil, err
	}

	if c.cfg.BindPassword != "" {
		err = l.Bind(c.cfg.BindDN, c.cfg.BindPassword)
	} else {
		err = l.UnauthenticatedBind(c.cfg.BindDN)
	}

	if err != nil {
		return nil, err
	}

	result, err := l.Search(&ldap.SearchRequest{
		BaseDN:     c.cfg.BaseDN,
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     fmt.Sprintf(c.cfg.Filter, userName),
		Attributes: c.cfg.Attributes,
	})

	if err != nil {
		return nil, err
	}

	if len(result.Entries) != 1 {
		return nil, ErrEntries
	}

	err = l.Bind(result.Entries[0].DN, password)

	if err != nil {
		return nil, err
	}

	id := ""
	ext := map[string][]string{}

	for _, attr := range result.Entries[0].Attributes {
		name := attr.Name
		values := attr.Values

		if name == "uid" {
			id = values[0]
			continue
		}

		ext[name] = values
	}

	return auth.NewDefaultUser(userName, id, nil, ext), nil
}

// New return new auth.Strategy.
func New(cfg *Config) auth.Strategy {
	c := client{
		dial: dial,
		cfg:  cfg,
	}
	return basic.AuthenticateFunc(c.authenticate)
}

// NewCached return new auth.Strategy.
// The returned strategy, caches the authentication decision.
func NewCached(cfg *Config, c store.Cache) auth.Strategy {
	cl := client{
		dial: dial,
		cfg:  cfg,
	}
	return basic.New(cl.authenticate, c)
}
