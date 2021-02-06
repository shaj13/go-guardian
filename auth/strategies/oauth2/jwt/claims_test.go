package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2"
)

func TestGetUserName(t *testing.T) {
	table := []struct {
		name     string
		ecpected string
		claims   oauth2.ClaimsResolver
	}{
		{
			name:     "IDToken: it return user name from info if exist",
			ecpected: "test-info",
			claims: IDToken{
				Info:              auth.NewUserInfo("test-info", "", nil, nil),
				Standard:          new(claims.Standard),
				PreferredUsername: "username",
				Email:             "test@test.com",
			},
		},
		{
			name:     "IDToken: it return user name from PreferredUsername claim if exist",
			ecpected: "test-username",
			claims: IDToken{
				Info:              auth.NewUserInfo("", "", nil, nil),
				Standard:          new(claims.Standard),
				PreferredUsername: "test-username",
				Email:             "test@test.com",
			},
		},
		{
			name:     "IDToken: it return user name from email claim if exist",
			ecpected: "test@test.com",
			claims: IDToken{
				Info:     auth.NewUserInfo("", "", nil, nil),
				Standard: new(claims.Standard),
				Email:    "test@test.com",
			},
		},
		{
			name:     "IDToken: it return user name from subject claim if exist",
			ecpected: "test-subject",
			claims: IDToken{
				Info: auth.NewUserInfo("", "", nil, nil),
				Standard: &claims.Standard{
					Subject: "test-subject",
				},
			},
		},
		{
			name:     "Claims: it return user name from info if exist",
			ecpected: "test-info",
			claims: Claims{
				Info: auth.NewUserInfo("test-info", "", nil, nil),
				Standard: &claims.Standard{
					Subject: "subject",
				},
			},
		},
		{
			name:     "Claims: it return user name from subject claim if exist",
			ecpected: "test-subject",
			claims: Claims{
				Info: auth.NewUserInfo("", "", nil, nil),
				Standard: &claims.Standard{
					Subject: "test-subject",
				},
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			username := tt.claims.Resolve().GetUserName()
			assert.Equal(t, tt.ecpected, username)
		})
	}
}

func TestGetID(t *testing.T) {
	table := []struct {
		name     string
		ecpected string
		claim    oauth2.ClaimsResolver
	}{
		{
			name:     "IDToken: it return user id from info if exist",
			ecpected: "test-info-id",
			claim: IDToken{
				Info: auth.NewUserInfo("", "test-info-id", nil, nil),
				Standard: &claims.Standard{
					Subject: "test-subject",
				},
			},
		},
		{
			name:     "IDToken: it return id from subject if exist",
			ecpected: "test-subject-id",
			claim: IDToken{
				Info: auth.NewUserInfo("", "", nil, nil),
				Standard: &claims.Standard{
					Subject: "test-subject-id",
				},
			},
		},
		{
			name:     "Claims: it return user id from info if exist",
			ecpected: "test-info-id",
			claim: Claims{
				Info: auth.NewUserInfo("", "test-info-id", nil, nil),
				Standard: &claims.Standard{
					Subject: "test-subject",
				},
			},
		},
		{
			name:     "Claims: it return id from subject if exist",
			ecpected: "test-subject-id",
			claim: Claims{
				Info: auth.NewUserInfo("", "", nil, nil),
				Standard: &claims.Standard{
					Subject: "test-subject-id",
				},
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			id := tt.claim.Resolve().GetID()
			assert.Equal(t, tt.ecpected, id)
		})
	}
}

func TestGetExpiresAt(t *testing.T) {
	exp := claims.Time(time.Now())
	table := []struct {
		name         string
		ecpectedZero bool
		claim        oauth2.ClaimsResolver
	}{
		{
			name:         "Claims: it return zero time if ExpirestAt is nil",
			ecpectedZero: true,
			claim: Claims{
				Standard: &claims.Standard{},
			},
		},
		{
			name: "Claims: it return time",
			claim: Claims{
				Standard: &claims.Standard{
					ExpiresAt: &exp,
				},
			},
		},
		{
			name:         "IDToken: it return zero time if ExpirestAt is nil",
			ecpectedZero: true,
			claim: IDToken{
				Standard: &claims.Standard{},
			},
		},
		{
			name: "IDToken: it return time",
			claim: IDToken{
				Standard: &claims.Standard{
					ExpiresAt: &exp,
				},
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			exp := oauth2.ExpiresAt(tt.claim)
			assert.Equal(t, tt.ecpectedZero, exp.IsZero())
		})
	}
}

func TestGetScope(t *testing.T) {
	scope := []string{"1", "2"}

	claim := &Claims{
		Standard: &claims.Standard{
			Scope: claims.StringOrList(scope),
		},
	}

	idToken := IDToken{
		Standard: &claims.Standard{
			Scope: claims.StringOrList(scope),
		},
	}

	for _, c := range []oauth2.ClaimsResolver{claim, idToken} {
		got := oauth2.Scope(c)
		assert.Equal(t, scope, got)
	}
}
