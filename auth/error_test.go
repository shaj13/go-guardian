package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidType(t *testing.T) {
	table := []struct {
		name    string
		want    interface{}
		got     interface{}
		wantStr string
		gotStr  string
	}{
		{
			name:    "it convert nil to string when want nil",
			want:    nil,
			got:     "",
			wantStr: "<nil>",
			gotStr:  "string",
		},
		{
			name:    "it convert nil to string when got nil",
			want:    "",
			got:     nil,
			gotStr:  "<nil>",
			wantStr: "string",
		},
		{
			name:    "it set want, got to strings using reflect",
			want:    "",
			got:     1,
			wantStr: "string",
			gotStr:  "int",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			err := NewTypeError("", tt.want, tt.got)
			it, ok := err.(TypeError)
			assert.True(t, ok)
			assert.Equal(t, tt.gotStr, it.Got)
			assert.Equal(t, tt.wantStr, it.Want)
			assert.Contains(t, err.Error(), tt.wantStr)
			assert.Contains(t, err.Error(), tt.gotStr)
		})
	}
}
