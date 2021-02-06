package userinfo

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/auth"
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
				Info:              auth.NewUserInfo("test-info", "", nil, nil),
				PreferredUsername: "username",
				Email:             "test@test.com",
			},
		},
		{
			name:     "it return user name from PreferredUsername claim if exist",
			ecpected: "test-username",
			claim: Claims{
				Info:              auth.NewUserInfo("", "", nil, nil),
				PreferredUsername: "test-username",
				Email:             "test@test.com",
			},
		},
		{
			name:     "it return user name from email claim if exist",
			ecpected: "test@test.com",
			claim: Claims{
				Info:  auth.NewUserInfo("", "", nil, nil),
				Email: "test@test.com",
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
				Info:    auth.NewUserInfo("", "test-info-id", nil, nil),
				Subject: "subject",
			},
		},
		{
			name:     "it return id from subject if exist",
			ecpected: "test-subject-id",
			claim: Claims{
				Info:    auth.NewUserInfo("", "", nil, nil),
				Subject: "test-subject-id",
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
