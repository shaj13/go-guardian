package auth

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthenticator(t *testing.T) {
	table := []struct {
		name       string
		strategies []Strategy
		paths      []string
		userId     string
		ExpetedErr bool
	}{
		{
			name: "it return error when all strategies return errors",
			strategies: []Strategy{
				strategy{returnErr: true},
				strategy{returnErr: true},
				strategy{returnErr: true},
			},
			ExpetedErr: true,
		},
		{
			name:       "it return error when no strategies enabled",
			ExpetedErr: true,
		},
		{
			name: "it return user info when first strategy return info",
			strategies: []Strategy{
				strategy{returnErr: true},
				strategy{id: "1"},
				strategy{returnErr: true},
			},
			ExpetedErr: false,
			userId:     "1",
		},
		{
			name:  "it return DisabledPath when path disabled",
			paths: []string{"/health", "health2", "/api/health"},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			authenticator := New(tt.paths...)
			r, _ := http.NewRequest("GET", "/", nil)

			for i, strategy := range tt.strategies {
				key := strconv.Itoa(i)
				authenticator.EnableStrategy(StrategyKey(key), strategy)
			}

			if len(tt.paths) > 0 {
				for _, p := range tt.paths {
					r.RequestURI = p
					_, err := authenticator.Authenticate(r)
					if err != DisabledPath {
						t.Errorf("Expected %v, Got %v, For Path %s", DisabledPath, err, p)
						continue
					}
				}
				return
			}

			info, err := authenticator.Authenticate(r)

			if tt.ExpetedErr {
				assert.True(t, err != nil, "Expected error got nil")
				return
			}

			assert.Equal(t, tt.userId, info.ID())
		})
	}
}

type strategy struct {
	id        string
	returnErr bool
}

func (s strategy) Authenticate(ctx context.Context, r *http.Request) (Info, error) {
	if s.returnErr {
		return nil, fmt.Errorf("authenticator test strategy L25")
	}
	return NewDefaultUser("", s.id, nil, nil), nil
}
