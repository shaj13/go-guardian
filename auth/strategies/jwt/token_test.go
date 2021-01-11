package jwt

import (
	"testing"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/stretchr/testify/assert"
)

func TestToken(t *testing.T) {
	info := &testUser{
		Name:       "test-user",
		ID:         "test-user-id",
		Role:       "test-user-role",
		Groups:     []string{"test-uesr-group"},
		Extensions: auth.Extensions{"test-user-ext-key": []string{"test-user-ext-value"}},
	}

	defer func() {
		ic := func(name, id string, groups []string, ext auth.Extensions) auth.Info {
			return auth.NewDefaultUser(name, id, groups, ext)
		}
		auth.SetInfoConstructor(ic)
	}()

	auth.SetInfoConstructor(func(_, _ string, _ []string, _ auth.Extensions) auth.Info {
		return new(testUser)
	})

	tk := new(accessToken)
	tk.s = StaticSecret{
		ID:     "kid",
		Secret: []byte("test-secret"),
		Method: jwt.SigningMethodHS256,
	}
	tk.d = time.Hour
	tk.iss = "test-iss"
	tk.aud = jwt.ClaimStrings{"test-aud"}

	str, err := tk.issue(info)
	assert.NoError(t, err)

	c, err := tk.parse(str)
	assert.NoError(t, err)
	assert.Equal(t, c.UserInfo, info)

}

func TestNewToken(t *testing.T) {
	tk := newAccessToken(nil)
	if assert.NotNil(t, tk) {
		assert.True(t, len(tk.aud) == 1)
		assert.True(t, len(tk.aud[0]) == 0)
		assert.True(t, len(tk.iss) > 0)
		assert.True(t, tk.d > 0)
	}
}

// testUser has been added to verify we still can marshal/unmarshal
// customized auth.info from jwt claims.
type testUser struct {
	Name       string
	Role       string
	ID         string
	Groups     []string
	Extensions auth.Extensions
}

func (d *testUser) GetUserName() string {
	return d.Name
}

func (d *testUser) SetUserName(name string) {
	d.Name = name
}

func (d *testUser) GetID() string {
	return d.ID
}

func (d *testUser) SetID(id string) {
	d.ID = id
}

func (d *testUser) GetGroups() []string {
	return d.Groups
}

func (d *testUser) SetGroups(groups []string) {
	d.Groups = groups
}

func (d *testUser) GetExtensions() auth.Extensions {
	return d.Extensions
}

func (d *testUser) SetExtensions(exts auth.Extensions) {
	d.Extensions = exts
}
