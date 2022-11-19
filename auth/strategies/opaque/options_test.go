package opaque

import (
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/shaj13/go-guardian/v2/auth"
)

func TestOptions(t *testing.T) {
	tests := []struct {
		defaults interface{}
		expected interface{}
		opt      auth.Option
		value    func(o *opaque) interface{}
	}{
		{
			defaults: "s",
			expected: "p",
			opt:      WithTokenPrefix("p"),
			value:    func(o *opaque) interface{} { return o.prefix },
		},
		{
			defaults: 24,
			expected: 32,
			opt:      WithTokenLength(32),
			value:    func(o *opaque) interface{} { return o.tokenLength },
		},
		{
			defaults: time.Hour * 24,
			expected: time.Hour,
			opt:      WithExpDuration(time.Hour),
			value:    func(o *opaque) interface{} { return o.exp },
		},
		{
			defaults: crypto.SHA512_256,
			expected: crypto.SHA256,
			opt:      WithHash(crypto.SHA256),
			value:    func(o *opaque) interface{} { return o.h },
		},
	}

	for _, tt := range tests {
		o1 := newOpaque(nil, nil)
		require.Equal(t, tt.defaults, tt.value(o1))

		o2 := newOpaque(nil, nil, tt.opt)
		require.Equal(t, tt.expected, tt.value(o2))
	}
}
