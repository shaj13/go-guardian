package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSetAudience(t *testing.T) {
	aud := "test"
	opt := SetAudience(aud)
	tk := newAccessToken(nil, opt)
	assert.Equal(t, aud, tk.aud)
}

func TestSetIssuer(t *testing.T) {
	opt := SetIssuer("test")
	tk := newAccessToken(nil, opt)
	assert.Equal(t, "test", tk.iss)
}

func TestSetExpDuration(t *testing.T) {
	opt := SetExpDuration(time.Hour)
	tk := newAccessToken(nil, opt)
	assert.Equal(t, time.Hour, tk.dur)
}
