package token

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/auth"
)

func TestNewStaticFromFile(t *testing.T) {
	table := []struct {
		name        string
		users       map[string]auth.Info
		file        string
		contains    string
		expectedErr bool
	}{
		{
			name:        "it return error when token alrady exist",
			file:        "invalid_token_exist",
			contains:    "token already exists",
			expectedErr: true,
		},
		{
			name:        "it return error when token empty",
			file:        "invalid_token",
			contains:    "a non empty token is required",
			expectedErr: true,
		},
		{
			name:        "it return error when column less than 3",
			file:        "invalid_columns",
			contains:    "3 columns (token, username, id)",
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
			strategy, err := NewStaticFromFile("testdata/" + tt.file + ".csv")
			if tt.expectedErr {
				assert.Error(t, err, "Expcted to return errors %v", tt.name)
				assert.Contains(
					t,
					err.Error(),
					tt.contains,
					"Expected error to contains: %v, Test Case %v",
					tt.contains,
					tt.name,
				)
				return
			}

			for k, v := range tt.users {
				r, _ := http.NewRequest("GET", "/", nil)
				r.Header.Set("Authorization", "Bearer "+k)
				info, err := strategy.Authenticate(r.Context(), r)
				assert.NoError(t, err)
				assert.EqualValues(t, v.GetID(), info.GetID())
				assert.EqualValues(t, v.GetUserName(), info.GetUserName())
				assert.EqualValues(t, v.GetGroups(), info.GetGroups())
				assert.EqualValues(t, v.GetExtensions(), info.GetExtensions())
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

	strategy := NewStatic(tokens)

	for k, v := range tokens {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer "+k)

		info, err := strategy.Authenticate(context.Background(), r)

		assert.NoError(t, err)
		assert.EqualValues(t, v.GetID(), info.GetID())
		assert.EqualValues(t, v.GetUserName(), info.GetUserName())
		assert.EqualValues(t, v.GetGroups(), info.GetGroups())
		assert.EqualValues(t, v.GetExtensions(), info.GetExtensions())
	}
}

func BenchmarkStaticToken(b *testing.B) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer token")

	tokens := map[string]auth.Info{
		"token": auth.NewDefaultUser("token", "1", nil, nil),
	}

	strategy := NewStatic(tokens)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := strategy.Authenticate(r.Context(), r)
			if err != nil {
				b.Error(err)
			}
		}
	})
}
