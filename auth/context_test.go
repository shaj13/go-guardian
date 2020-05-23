package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUser(t *testing.T) {
	table := []struct {
		name string
		info Info
	}{
		{
			name: "it return user info from request",
			info: NewDefaultUser("test", "1", nil, nil),
		},
		{
			name: "it return nil when user info nil",
			info: nil,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			r = RequestWithUser(tt.info, r)
			info := User(r)
			assert.Equal(t, tt.info, info)
		})
	}

}
