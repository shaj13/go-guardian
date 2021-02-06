package introspection

import (
	"encoding/json"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2"
)

// Claims represents introspection response as defined in RFC 7662.
// Claims implements auth.Info and oauth2.ClaimsResolver.
type Claims struct {
	Active    bool   `json:"active"`
	ClientID  string `json:"client_id"`
	UserName  string `json:"username"`
	TokenType string `json:"token_type"`
	auth.Info
	*claims.Standard
}

// New return's a new Claims as oauth2.ClaimsResolver.
func (c Claims) New() oauth2.ClaimsResolver {
	return &Claims{
		Info:     auth.NewUserInfo("", "", []string{}, make(auth.Extensions)),
		Standard: new(claims.Standard),
	}
}

// Resolve return's c as auth.Info.
func (c Claims) Resolve() auth.Info {
	return c
}

// GetUserName return's c.Info.GetUserName if exist,
// Otherwise, it return c.UserName or c.Subject.
func (c Claims) GetUserName() string {
	switch {
	case len(c.Info.GetUserName()) > 0:
		return c.Info.GetUserName()
	case len(c.UserName) > 0:
		return c.UserName
	default:
		return c.Subject
	}
}

// GetID return's c.Info.GetID if exist,
// Otherwise, it return c.Subject.
func (c Claims) GetID() string {
	if len(c.Info.GetID()) > 0 {
		return c.Info.GetID()
	}
	return c.Subject
}

// GetExpiresAt return's c.ExpiresAt.
func (c Claims) GetExpiresAt() time.Time {
	if c.ExpiresAt == nil {
		return time.Time{}
	}
	return time.Time(*c.ExpiresAt)
}

// GetScope return's c.Scope splited by space or comma.
func (c Claims) GetScope() []string {
	return c.Scope.Split()
}

type claimsResponse struct {
	Active bool
	oauth2.ClaimsResolver
}

func (c *claimsResponse) UnmarshalJSON(b []byte) error {
	v := struct {
		Active bool `json:"active"`
	}{}

	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}

	c.Active = v.Active
	return json.Unmarshal(b, &c.ClaimsResolver)
}
