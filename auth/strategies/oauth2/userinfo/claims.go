package userinfo

import (
	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2"
)

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

// Claims represents standard claims as defined in OpenID
// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims.
// Claims implements auth.Info and oauth2.ClaimsResolver.
type Claims struct {
	Subject             string       `json:"sub,omitempty"`
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
	auth.Info
}

// New return's a new Claims as oauth2.ClaimsResolver.
func (c Claims) New() oauth2.ClaimsResolver {
	return &Claims{
		Info: auth.NewUserInfo("", "", []string{}, make(auth.Extensions)),
	}
}

// Resolve return's c as auth.Info.
func (c Claims) Resolve() auth.Info {
	return c
}

// GetUserName return's c.Info.GetUserName if exist,
// Otherwise, it return c.PreferredUsername or c.Email.
func (c Claims) GetUserName() string {
	switch {
	case len(c.Info.GetUserName()) > 0:
		return c.Info.GetUserName()
	case len(c.PreferredUsername) > 0:
		return c.PreferredUsername
	default:
		return c.Email
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

// Verify always return a nil error.
func (c Claims) Verify(opts claims.VerifyOptions) (err error) { return }
