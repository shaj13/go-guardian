package errors

import (
	"fmt"
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
			err := NewInvalidType(tt.want, tt.got)
			it, ok := err.(InvalidType)
			assert.True(t, ok)
			assert.Equal(t, tt.gotStr, it.Got)
			assert.Equal(t, tt.wantStr, it.Want)
			assert.Contains(t, err.Error(), tt.wantStr)
			assert.Contains(t, err.Error(), tt.gotStr)
		})
	}
}

func TestError(t *testing.T) {
	table := []struct {
		errs   MultiError
		errStr string
	}{
		{
			errs: MultiError{
				fmt.Errorf("1st error"),
				fmt.Errorf("2nd error"),
				fmt.Errorf("3rd error"),
			},
			errStr: "1st error: [2nd error, 3rd error, ]",
		},
		{
			errs:   MultiError{},
			errStr: "",
		},
		{
			errs: MultiError{
				fmt.Errorf("Test error"),
			},
			errStr: "Test error",
		},
	}

	for _, tt := range table {
		assert.Equal(t, tt.errs.Error(), tt.errStr)
	}
}
