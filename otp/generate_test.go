package otp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateOTP(t *testing.T) {
	otp, err := GenerateOTP("GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA", 0, SHA1, SixDigits)
	assert.Nil(t, err)
	assert.Equal(t, otp, "639434")
}

func TestGenerateSecret(t *testing.T) {
	// Round #1 it return error when secretsize < 16
	_, err := GenerateSecret(1)
	assert.EqualError(t, err, ErrWeakSecretSize.Error())

	// Round #2 it return nil error and secret
	str, err := GenerateSecret(20)
	assert.Equal(t, len(str), 32)
	assert.Nil(t, err)
}
