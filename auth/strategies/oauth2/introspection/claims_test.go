package introspection

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2"
)

func TestClaimGetUserName(t *testing.T) {
	table := []struct {
		name     string
		ecpected string
		claim    Claims
	}{
		{
			name:     "it return user name from info if exist",
			ecpected: "test-info",
			claim: Claims{
				Info:     auth.NewUserInfo("test-info", "", nil, nil),
				UserName: "username",
				Standard: &claims.Standard{
					Subject: "subject",
				},
			},
		},
		{
			name:     "it return user name from claim if exist",
			ecpected: "test-username",
			claim: Claims{
				Info:     auth.NewUserInfo("", "", nil, nil),
				UserName: "test-username",
				Standard: &claims.Standard{
					Subject: "subject",
				},
			},
		},
		{
			name:     "it return user name from claim if exist",
			ecpected: "test-subject",
			claim: Claims{
				Info: auth.NewUserInfo("", "", nil, nil),
				Standard: &claims.Standard{
					Subject: "test-subject",
				},
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			username := tt.claim.GetUserName()
			assert.Equal(t, tt.ecpected, username)
		})
	}
}

func TestClaimGetID(t *testing.T) {
	table := []struct {
		name     string
		ecpected string
		claim    Claims
	}{
		{
			name:     "it return user id from info if exist",
			ecpected: "test-info-id",
			claim: Claims{
				Info: auth.NewUserInfo("", "test-info-id", nil, nil),
				Standard: &claims.Standard{
					Subject: "subject",
				},
			},
		},
		{
			name:     "it return id from subject if exist",
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
			username := tt.claim.GetID()
			assert.Equal(t, tt.ecpected, username)
		})
	}
}

func TestClaimGetExpiresAt(t *testing.T) {
	exp := claims.Time(time.Now())
	table := []struct {
		name         string
		ecpectedZero bool
		claim        Claims
	}{
		{
			name:         "it return zero time if ExpirestAt is nil",
			ecpectedZero: true,
			claim: Claims{
				Standard: &claims.Standard{},
			},
		},
		{
			name: "it return time",
			claim: Claims{
				Standard: &claims.Standard{
					ExpiresAt: &exp,
				},
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			exp := tt.claim.GetExpiresAt()
			assert.Equal(t, tt.ecpectedZero, exp.IsZero())
		})
	}
}

func TestClaimExpiresAt(t *testing.T) {
	exp := claims.Time(time.Now())
	c := &Claims{
		Standard: &claims.Standard{
			ExpiresAt: &exp,
		},
	}

	got := oauth2.ExpiresAt(c)
	assert.Equal(t, time.Time(exp), got)
}

func TestClaimScope(t *testing.T) {
	scope := []string{"1", "2"}
	c := &Claims{
		Standard: &claims.Standard{
			Scope: claims.StringOrList(scope),
		},
	}

	got := oauth2.Scope(c)
	assert.Equal(t, scope, got)
}
