package auth

import (
	"fmt"
	"testing"

	"github.com/magiconair/properties/assert"
)

func TestError(t *testing.T) {
	errs := authError{
		fmt.Errorf("1st error"),
		fmt.Errorf("2nd error"),
		fmt.Errorf("3rd error"),
	}

	assert.Equal(t, errs.Error(), "1st error: [2nd error, 3rd error, ]")
}
