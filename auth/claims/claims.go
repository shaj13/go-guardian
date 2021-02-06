// Package claims collects common jwt types.
package claims

import (
	"crypto/subtle"
	"encoding/json"
	"strings"
	"time"
)

const (
	// DefaultLeeway defines the default leeway to verify time claim.
	DefaultLeeway = time.Minute
)

// InvalidReason represents claim verification error reason.
type InvalidReason int

const (
	// Expired results when a claim has expired, based on the time
	// given in the VerifyOptions.
	Expired InvalidReason = iota
	// NotBefore results when a claim not yet valid, based on the time
	// given in the VerifyOptions.
	NotBefore
	// IssuerMismatch results when the issuer name of a claim
	// does not match the issuer name given in the VerifyOptions.
	IssuerMismatch
	// IssuedAtFuture results when the issued at (iat) time of a claim,
	// is after the time given in the VerifyOptions.
	IssuedAtFuture
	// AudienceNotFound results when a claim audience
	// does not have one of the audiences given in the VerifyOptions.
	AudienceNotFound
)

// InvalidError results when an odd error occurs in Standard.Verify.
type InvalidError struct {
	Claims Standard
	Opts   VerifyOptions
	Reason InvalidReason
}

func (e InvalidError) Error() string {
	switch e.Reason {
	case NotBefore:
		return "claims: standard claims not yet valid"
	case Expired:
		return "claims: standard claims has expired"
	case IssuerMismatch:
		return "claims: standard claims issuer name does not match the expected issuer"
	case IssuedAtFuture:
		return "claims: standard claims issued at a future time"
	case AudienceNotFound:
		return "claims: standard claims audience does not have one of the expected audiences"
	}

	return "claims: unknown error"
}

// StringOrList define a type for a claim that
// can be either a string or list of strings.
type StringOrList []string

// UnmarshalJSON to string or array of strings.
func (s *StringOrList) UnmarshalJSON(b []byte) error {
	v := []string{}
	if err := json.Unmarshal(b, &v); err == nil {
		*s = v
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	*s = []string{str}
	return nil
}

// Split slices claim string into all substrings separated by comma or space and
// returns a slice of the substrings between those separators.
// Otherwise, it returns claim list as is.
func (s StringOrList) Split() []string {
	if len(s) > 1 || len(s) == 0 {
		return s
	}

	str := s[0]
	delimiter := ","
	if !strings.Contains(str, delimiter) {
		delimiter = " "
	}
	return strings.Split(str, delimiter)
}

// Time defines a timestamp encoded as time.Unix in JSON
type Time time.Time

// MarshalJSON encode t as time.Unix.
func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).Unix())
}

// UnmarshalJSON decode json time.Unix to t.
func (t *Time) UnmarshalJSON(b []byte) (err error) {
	var sec int64
	if err := json.Unmarshal(b, &sec); err != nil {
		return err
	}
	*(*time.Time)(t) = time.Unix(sec, 0)
	return nil
}

// VerifyOptions contains parameters for Standard.Verify.
type VerifyOptions struct {
	// Audience represents targeted claim audiences.
	Audience []string
	// Issuer represents claim issuer.
	Issuer string
	// Time returns the current time.
	// If Time is nil, Standard.Verify uses time.Now with DefaultLeeway.
	// Recommended to add leeway window before return t to account for clock skew,
	// https://tools.ietf.org/html/rfc7519#section-4.1.4.
	//
	// 		func() (time.Time) {
	//	        return time.Now().Add(-leeway)
	//       }
	Time func() (t time.Time)
	// Extra parameters.
	Extra map[string]interface{}
}

// Standard provide a starting point for a set of useful interoperable claims
// as defined in RFC 7519.
type Standard struct {
	Scope     StringOrList `json:"scope,omitempty"`
	Audience  StringOrList `json:"aud,omitempty"`
	ExpiresAt *Time        `json:"exp,omitempty"`
	IssuedAt  *Time        `json:"iat,omitempty"`
	NotBefore *Time        `json:"nbf,omitempty"`
	Subject   string       `json:"sub,omitempty"`
	Issuer    string       `json:"iss,omitempty"`
	JWTID     string       `json:"jti,omitempty"`
}

// Verify attempts to verify s using opts.
func (s Standard) Verify(opts VerifyOptions) error {
	fail := func(r InvalidReason) error {
		return InvalidError{
			Opts: opts,
			// TODO: copy to an clone method.
			Claims: Standard{
				Scope:     s.Scope,
				Audience:  s.Audience,
				ExpiresAt: s.ExpiresAt,
				IssuedAt:  s.IssuedAt,
				NotBefore: s.NotBefore,
				Subject:   s.Subject,
				Issuer:    s.Issuer,
				JWTID:     s.JWTID,
			},
			Reason: r,
		}
	}

	verifyString := func(a, b string) bool {
		return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
	}

	verifyStringList := func(a, b []string) bool {
		match := make(map[string]struct{})
		for _, v := range a {
			match[v] = struct{}{}
		}

		for _, v := range b {
			if _, ok := match[v]; ok {
				return verifyString(v, v)
			}
		}

		// just to add a constant time to prevent timing attacks.
		_ = verifyString(a[0], a[0])
		return false
	}

	verifyTime := func(a, b time.Time) bool {
		ok := a.Before(b)
		// just to add a constant time to prevent timing attacks.
		_ = verifyString(a.String(), a.String())
		return ok
	}

	if opts.Time == nil {
		opts.Time = func() (t time.Time) {
			return time.Now().Add(-DefaultLeeway)
		}
	}

	if len(opts.Issuer) > 0 && !verifyString(opts.Issuer, s.Issuer) {
		return fail(IssuerMismatch)
	}

	if len(opts.Audience) > 0 && !verifyStringList(opts.Audience, s.Audience) {
		return fail(AudienceNotFound)
	}

	if !opts.Time().IsZero() && s.ExpiresAt != nil && !verifyTime(opts.Time(), time.Time(*s.ExpiresAt)) {
		return fail(Expired)
	}

	if !opts.Time().IsZero() && s.NotBefore != nil && !verifyTime(time.Time(*s.NotBefore), opts.Time()) {
		return fail(NotBefore)
	}

	if !opts.Time().IsZero() && s.IssuedAt != nil && !verifyTime(time.Time(*s.IssuedAt), opts.Time()) {
		return fail(IssuedAtFuture)
	}

	return nil
}
