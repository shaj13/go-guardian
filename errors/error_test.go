package errors

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
			got:     "",
			wantStr: "string",
			gotStr:  "string",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			err := NewInvalidType(tt.want, tt.got)
			it, ok := err.(InvalidType)
			assert.True(t, ok)
			assert.Equal(t, tt.gotStr, it.Got)
			assert.Equal(t, tt.wantStr, it.Want)
		})
	}
}
