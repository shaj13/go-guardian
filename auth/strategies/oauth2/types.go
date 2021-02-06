package oauth2

import (
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/claims"
)

var _ ErrorResolver = ResponseError{}

// ClaimsResolver provides context information about an authorization response.
type ClaimsResolver interface {
	// New returns new instance pointer from the same type.
	New() ClaimsResolver
	// Verify the authorization response claims.
	Verify(claims.VerifyOptions) error
	// Resolve returns user info resolved from the authorization response claims.
	Resolve() auth.Info
}

// ErrorResolver provides context information about an
// authorization error response.
type ErrorResolver interface {
	error
	// New returns new instance pointer from the same type.
	New() ErrorResolver
}

// ResponseError implements ErrorResolver and provides context information about an
// authorization error response as defined in RFC 6749.
type ResponseError struct {
	// Reason is the error reason or code,
	// In RFC 6749 called error.
	Reason string `json:"error"`
	// URI identifying a human-readable web page with
	// information about the error.
	URI string `json:"error_uri"`
	// Description is a text providing additional information,
	// used to assist in understanding the error that occurred.
	Description string `json:"error_description"`
}

func (e ResponseError) Error() string {
	return "strategies/oauth2: " + e.Reason + ", " + e.Description
}

// New returns new ResponseError as ErrorResolver.
func (e ResponseError) New() ErrorResolver {
	return new(ResponseError)
}

// ExpiresAt returns the result of calling the GetExpiresAt method on c,
// if c type contains an GetExpiresAt method returning time. Otherwise, ExpiresAt returns zero time.
func ExpiresAt(c ClaimsResolver) time.Time {
	e, ok := c.(interface {
		GetExpiresAt() time.Time
	})
	if !ok {
		return time.Time{}
	}
	return e.GetExpiresAt()
}

// Scope returns the result of calling the GetScope method on c,
// if c type contains an GetScope method returning slice of strings. Otherwise, Scope returns empty slice.
func Scope(c ClaimsResolver) []string {
	s, ok := c.(interface {
		GetScope() []string
	})
	if !ok {
		return []string{}
	}
	return s.GetScope()
}
