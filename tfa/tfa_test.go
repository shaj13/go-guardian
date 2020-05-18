package tfa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrMissingValues(t *testing.T) {
	table := []struct {
		cfg *OTPConfig
		err error
	}{
		{
			cfg: &OTPConfig{},
			err: ErrWeakSecretSize,
		},
		{
			cfg: &OTPConfig{Label: "Label", SecretSize: 20},
			err: ErrInvalidOTPTypeE,
		},
		{
			cfg: &OTPConfig{SecretSize: 20},
			err: ErrMissingLabel,
		},
	}

	for _, tt := range table {
		_, _, err := NewOTP(tt.cfg)
		if err != tt.err {
			t.Errorf("Expected %v , Got %v", tt.err, err)
		}
	}
}

func TestDefaultValues(t *testing.T) {
	cfg := &OTPConfig{
		SecretSize: 20,
		OTPType:    TOTP,
		Label:      "Test",
	}
	NewOTP(cfg)

	assert.Greaterf(t, len(cfg.Secret), 0, "Expected Secret to be generated, Got %s", cfg.Secret)
	assert.Equal(t, cfg.Digits, SixDigits, "Expected Digits as default to be 6, Got %s", cfg.Digits)
	assert.Equal(t, cfg.HashAlgorithm, SHA1, "Expected HashAlgorithm as default to be SHA1, Got %s", cfg.HashAlgorithm)
	assert.Equal(t, cfg.MaxAttempts, uint(3), "Expected MaxAttempts as default to be 3, Got %v", cfg.MaxAttempts)
	assert.Equal(t, cfg.LockOutDelay, uint(30), "Expected LockOutDelay as default to be 30, Got %v", cfg.LockOutDelay)
	assert.Equal(t, cfg.Period, uint64(30), "Expected Period as default to be 30, Got %v", cfg.Period)
}

func TestNewOTPFromKey(t *testing.T) {
	table := []struct {
		name              string // test case name
		key               string
		account           string
		label             string
		otpType           OTPType
		secret            string
		counter           uint64
		digits            Digits
		Algorithm         HashAlgorithm
		period            uint64
		issuer            string
		issuerLabelPrefix string
	}{
		{
			name:              "Full TOTP key",
			key:               "otpauth://totp/TEST%3Asample%40test.com?secret=GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA&issuer=TEST&algorithm=SHA512&digits=8&period=60",
			period:            60,
			label:             "TEST:sample@test.com",
			account:           "sample@test.com",
			issuer:            "TEST",
			issuerLabelPrefix: "TEST",
			counter:           0,
			otpType:           TOTP,
			secret:            "GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA",
			digits:            EightDigits,
			Algorithm:         SHA512,
		},
		{
			name:              "Full HOTP key",
			key:               "otpauth://hotp/TEST%3Asample%40test.com?secret=GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA&issuer=TEST&algorithm=SHA1&digits=6&counter=60",
			period:            0,
			label:             "TEST:sample@test.com",
			account:           "sample@test.com",
			issuer:            "TEST",
			issuerLabelPrefix: "TEST",
			counter:           60,
			otpType:           HOTP,
			secret:            "GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA",
			digits:            SixDigits,
			Algorithm:         SHA1,
		},
		{
			name:              "HOTP missing params",
			key:               "otpauth://hotp/TEST?secret=GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA",
			period:            0,
			label:             "TEST",
			account:           "",
			issuer:            "",
			issuerLabelPrefix: "",
			counter:           0,
			otpType:           HOTP,
			secret:            "GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA",
			digits:            SixDigits,
			Algorithm:         SHA1,
		},
		{
			name:              "TOTP missing params",
			key:               "otpauth://totp/TEST?secret=GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA",
			period:            30,
			label:             "TEST",
			account:           "",
			issuer:            "",
			issuerLabelPrefix: "",
			counter:           0,
			otpType:           TOTP,
			secret:            "GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA",
			digits:            SixDigits,
			Algorithm:         SHA1,
		},
		{
			name:              "TOTP invalid params",
			key:               "otpauth://totp/TEST?secret=GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA&digits=abc&period=abc",
			period:            30,
			label:             "TEST",
			account:           "",
			issuer:            "",
			issuerLabelPrefix: "",
			counter:           0,
			otpType:           TOTP,
			secret:            "GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA",
			digits:            SixDigits,
			Algorithm:         SHA1,
		},
		{
			name:              "HOTP invalid params",
			key:               "otpauth://hotp/TEST?secret=GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA&digits=abc&counter=abc",
			period:            0,
			label:             "TEST",
			account:           "",
			issuer:            "",
			issuerLabelPrefix: "",
			counter:           0,
			otpType:           HOTP,
			secret:            "GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA",
			digits:            SixDigits,
			Algorithm:         SHA1,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			key, OTP, err := NewOTPFromKey(tt.key)
			assert.NotNil(t, OTP)
			assert.Nil(t, err)
			assert.Equal(t, tt.account, key.AccountName())
			assert.Equal(t, tt.counter, key.Counter())
			assert.Equal(t, tt.period, key.Period())
			assert.Equal(t, tt.secret, key.Secret())
			assert.Equal(t, tt.Algorithm, key.Algorithm())
			assert.Equal(t, tt.digits, key.Digits())
			assert.Equal(t, tt.otpType, key.Type())
			assert.Equal(t, tt.issuerLabelPrefix, key.IssuerLabelPrefix())
			assert.Equal(t, tt.issuer, key.Issuer())
			assert.Equal(t, tt.label, key.Label())
			assert.Equal(t, tt.issuer, key.Issuer())
		})
	}
}

func TestGenerateCode(t *testing.T) {
	table := []struct {
		name  string
		code  string
		valid bool
	}{
		{
			name:  "counter 0 and valid code",
			code:  "345515",
			valid: true,
		},
		{
			name:  "counter 1 and valid code",
			code:  "422283",
			valid: true,
		},
		{
			name:  "counter 2 and Invalid code",
			code:  "0",
			valid: false,
		},
	}

	_, otp, _ := NewOTPFromKey("otpauth://hotp/TEST%3Asample%40test.com?secret=GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA&issuer=TEST&algorithm=SHA1&digits=6&counter=0")

	for i, tt := range table {
		if i == 1 {
			t.Log("here")
		}
		valid, err := otp.Verify(tt.code)
		assert.Nil(t, err)
		assert.Equal(t, tt.valid, valid, tt.name)
	}
}
