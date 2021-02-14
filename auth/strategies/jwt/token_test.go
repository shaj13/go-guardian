package jwt

import (
	"testing"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"

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
	tk.keeper = StaticSecret{
		ID:        "kid",
		Secret:    []byte("test-secret"),
		Algorithm: HS256,
	}
	tk.dur = time.Hour
	tk.iss = "test-iss"
	tk.aud = "test-aud"

	str, err := tk.issue(info)
	assert.NoError(t, err)

	c, err := tk.parse(str)
	assert.NoError(t, err)
	assert.Equal(t, c.UserInfo, info)
}

func TestTokenAlg(t *testing.T) {
	info := auth.NewDefaultUser("test", "test", nil, nil)

	hs512 := StaticSecret{
		ID:        "kid",
		Secret:    []byte("test-secret"),
		Algorithm: HS512,
	}

	hs256 := StaticSecret{
		ID:        "kid",
		Secret:    []byte("test-secret"),
		Algorithm: HS256,
	}

	tk := newAccessToken(hs512)

	str, err := tk.issue(info)
	assert.NoError(t, err)

	tk.keeper = hs256
	_, err = tk.parse(str)
	assert.Equal(t, ErrInvalidAlg, err)
}

func TestTokenKID(t *testing.T) {
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.P4Lqll22jQQJ1eMJikvNg5HKG-cKB0hUZA9BZFIG7Jk"
	tk := newAccessToken(nil)
	_, err := tk.parse(str)
	assert.Equal(t, ErrMissingKID, err)
}

func TestNewToken(t *testing.T) {
	tk := newAccessToken(nil)
	if assert.NotNil(t, tk) {
		assert.True(t, len(tk.aud) == 0)
		assert.True(t, len(tk.iss) == 0)
		assert.True(t, tk.dur > 0)
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
