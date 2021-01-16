package token

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/auth"
)

func TestSetType(t *testing.T) {
	cached := new(cachedToken)
	static := new(static)
	typ := Type("test")

	opt := SetType(typ)

	opt.Apply(cached)
	opt.Apply(static)

	assert.Equal(t, cached.typ, typ)
	assert.Equal(t, static.ttype, typ)
}

func TestSetParser(t *testing.T) {
	cached := new(cachedToken)
	static := new(static)
	p := XHeaderParser("")

	opt := SetParser(p)

	opt.Apply(cached)
	opt.Apply(static)

	assert.True(t, cached.parser != nil)
	assert.True(t, static.parser != nil)
}

func TestSetVerify(t *testing.T) {
	v := func(_ context.Context, _ *http.Request, _ auth.Info, _ string) error {
		return nil
	}

	cached := new(cachedToken)
	static := new(static)

	opt := SetVerify(v)

	opt.Apply(cached)
	opt.Apply(static)

	assert.True(t, cached.verify != nil)
	assert.True(t, static.verify != nil)
}
