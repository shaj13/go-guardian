package jwt

import (
	"time"

	"github.com/m87carlson/go-guardian/v2/auth"
	"github.com/m87carlson/go-guardian/v2/auth/claims"
	"github.com/m87carlson/go-guardian/v2/auth/strategies/oauth2"
)

// Claims represents JWT access token claims
// and provide a starting point for a set of useful interoperable claims
// as defined in RFC 7519.
// Claims implements auth.Info and oauth2.ClaimsResolver.
type Claims struct {
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

// GetUserName returns c.Info.GetUserName if exist,
// Otherwise, it return c.UserName or c.Subject.
func (c Claims) GetUserName() string {
	return pick(
		c.Info.GetUserName(),
		c.Subject,
	)
}

// GetID returns c.Info.GetID if exist,
// Otherwise, return's c.Subject.
func (c Claims) GetID() string {
	return pick(
		c.Info.GetID(),
		c.Subject,
	)
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

// AddressClaim represents a physical mailing address as defined in OpenID
// https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim.
type AddressClaim struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

// IDToken represents id token claims as defined in OpenID
// https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken.
// IDToken implements auth.Info and oauth2.ClaimsResolver.
type IDToken struct {
	Name                string       `json:"name,omitempty"`
	GivenName           string       `json:"given_name,omitempty"`
	FamilyName          string       `json:"family_name,omitempty"`
	MiddleName          string       `json:"middle_name,omitempty"`
	NickName            string       `json:"nickname,omitempty"`
	PreferredUsername   string       `json:"preferred_username,omitempty"`
	Profile             string       `json:"profile,omitempty"`
	Picture             string       `json:"picture,omitempty"`
	Website             string       `json:"website,omitempty"`
	Email               string       `json:"email,omitempty"`
	Gender              string       `json:"gender,omitempty"`
	Birthdate           string       `json:"birthdate,omitempty"`
	ZoneInfo            string       `json:"zoneinfo,omitempty"`
	Locale              string       `json:"locale,omitempty"`
	PhoneNumber         string       `json:"phone_number,omitempty"`
	PhoneNumberVerified bool         `json:"phone_number_verified,omitempty"`
	EmailVerified       bool         `json:"email_verified,omitempty"`
	Address             AddressClaim `json:"address,omitempty"`
	UpdatedAT           *claims.Time `json:"updated_at,omitempty"`

	Nonce           string       `json:"nonce,omitempty"`
	AuthContextRef  string       `json:"acr,omitempty"`
	AuthorizedParty string       `json:"azp,omitempty"`
	AccessTokenHash string       `json:"at_hash,omitempty"`
	CodeHash        string       `json:"c_hash,omitempty"`
	AuthMethodRef   []string     `json:"amr,omitempty"`
	AuthTime        *claims.Time `json:"auth_time,omitempty"`

	*claims.Standard
	auth.Info
}

// New return's a new IDToken as oauth2.ClaimsResolver.
func (it IDToken) New() oauth2.ClaimsResolver {
	return &IDToken{
		Info:     auth.NewUserInfo("", "", []string{}, make(auth.Extensions)),
		Standard: new(claims.Standard),
	}
}

// Resolve return's "id token" as auth.Info.
func (it IDToken) Resolve() auth.Info {
	return it
}

// GetUserName return's it.Info.GetUserName if exist,
// Otherwise, fallback to it.PreferredUsername/it.Email/it.Subject.
func (it IDToken) GetUserName() string {
	return pick(
		it.Info.GetUserName(),
		it.PreferredUsername,
		it.Email,
		it.Subject,
	)
}

// GetID returns it.Info.GetID if exist,
// Otherwise, return's it.Subject.
func (it IDToken) GetID() string {
	return pick(it.Info.GetID(), it.Subject)
}

// GetExpiresAt return's it.ExpiresAt.
func (it IDToken) GetExpiresAt() time.Time {
	if it.ExpiresAt == nil {
		return time.Time{}
	}
	return time.Time(*it.ExpiresAt)
}

// GetScope return's it.Scope splited by space or comma.
func (it IDToken) GetScope() []string {
	return it.Scope.Split()
}

func pick(candidates ...string) string {
	for _, c := range candidates {
		if len(c) > 0 {
			return c
		}
	}
	return ""
}
