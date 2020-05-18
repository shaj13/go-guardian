package bearer

import (
	"context"
	"testing"

	"github.com/shaj13/go-passport/auth"
	"github.com/stretchr/testify/assert"
)

func TestNewStaticFromFile(t *testing.T) {
	table := []struct {
		name        string
		users       map[string]auth.Info
		file        string
		conatins    string
		expectedErr bool
	}{
		{
			name:        "it return error when token alrady exist",
			file:        "invalid_token_exist",
			conatins:    "token already exists",
			expectedErr: true,
		},
		{
			name:        "it return error when token empty",
			file:        "invalid_token",
			conatins:    "a non empty token is required",
			expectedErr: true,
		},
		{
			name:        "it return error when column less than 3",
			file:        "invalid_columns",
			conatins:    "3 columns (token, username, id)",
			expectedErr: true,
		},
		{
			name: "it parse file and create static tokens when file valid",
			file: "valid",
			users: map[string]auth.Info{
				"testUserToken":  auth.NewDefaultUser("testUser", "1", []string{"group1"}, nil),
				"testUserToken3": auth.NewDefaultUser("testUser3", "3", nil, nil),
				"testUserToken2": auth.NewDefaultUser(
					"testUser2",
					"2",
					[]string{"group1", "group2"},
					map[string][]string{
						"extension": {"1"},
						"example":   {"2"},
					}),
			},
			expectedErr: false,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			strat, err := NewStaticFromFile("testdata/" + tt.file + ".csv")
			if tt.expectedErr {
				assert.Error(t, err, "Expcted to return errors %v", tt.name)
				assert.Contains(t, err.Error(), tt.conatins, "Expected error to contains: %v, Test Case %v", tt.conatins, tt.name)
				return
			}

			for k, v := range tt.users {
				static := strat.(*Static)
				info, err := static.authenticate(context.Background(), nil, k)

				assert.NoError(t, err)
				assert.EqualValues(t, v.ID(), info.ID())
				assert.EqualValues(t, v.UserName(), info.UserName())
				assert.EqualValues(t, v.Groups(), info.Groups())
				assert.EqualValues(t, v.Extensions(), info.Extensions())
			}
		})
	}
}

func TestNewStatic(t *testing.T) {
	tokens := map[string]auth.Info{
		"testUserToken":  auth.NewDefaultUser("testUser", "1", []string{"group1"}, nil),
		"testUserToken3": auth.NewDefaultUser("testUser3", "3", nil, nil),
		"testUserToken2": auth.NewDefaultUser(
			"testUser2",
			"2",
			[]string{"group1", "group2"},
			map[string][]string{
				"extension": {"1"},
				"example":   {"2"},
			}),
	}

	strat := NewStatic(tokens)

	for k, v := range tokens {
		static := strat.(*Static)
		info, err := static.authenticate(context.Background(), nil, k)

		assert.NoError(t, err)
		assert.EqualValues(t, v.ID(), info.ID())
		assert.EqualValues(t, v.UserName(), info.UserName())
		assert.EqualValues(t, v.Groups(), info.Groups())
		assert.EqualValues(t, v.Extensions(), info.Extensions())
	}
}
