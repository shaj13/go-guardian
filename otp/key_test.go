package otp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewKey(t *testing.T) {
	key := NewKey(HOTP, "label", "secret")
	assert.NotNil(t, key)
	assert.Equal(t, key.String(), "otpauth://hotp/label?secret=secret")
}

func TestNewKeyFromRaw(t *testing.T) {
	// Round #1, url parse error
	key, err := NewKeyFromRaw("[%10::1]")
	assert.Nil(t, key)
	assert.Error(t, err)

	//Round #2, url parsed
	key, err = NewKeyFromRaw("otpauth://hotp/label?secret=secret")
	assert.Nil(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, key.Type(), HOTP)
}

func TestKeyType(t *testing.T) {
	key := NewKey(HOTP, "", "")
	key.SetType(TOTP)
	assert.Equal(t, key.Type(), TOTP)
}

func TestKeyLabel(t *testing.T) {
	label := "label"
	key := NewKey(HOTP, "", "")
	key.SetLabel(label)
	assert.Equal(t, key.Label(), label)
}

func TestKeySecret(t *testing.T) {
	Secret := "test"
	key := NewKey(HOTP, "", "")
	key.SetSecret(Secret)
	assert.Equal(t, key.Secret(), Secret)
}

func TestKeyDigits(t *testing.T) {
	key := NewKey(HOTP, "", "")
	// Round #1 -- default digits
	assert.Equal(t, key.Digits(), SixDigits)

	// Round #2 set digits
	key.SetDigits(EightDigits)
	assert.Equal(t, key.Digits(), EightDigits)
}

func TestKeyIssuer(t *testing.T) {
	issuer := "test"
	key := NewKey(HOTP, "", "")
	key.SetIssuer(issuer)
	assert.Equal(t, key.Issuer(), issuer)
}

func TestKeyIssuerLabelPrefix(t *testing.T) {
	issuer := "prefix:accountname"
	key := NewKey(HOTP, "", "")
	// Round #1 return prefix if exist
	key.SetLabel(issuer)
	assert.Equal(t, key.IssuerLabelPrefix(), "prefix")

	// Round #2 empty prefix
	key.SetLabel("prefix")
	assert.Equal(t, key.IssuerLabelPrefix(), "")
}

func TestKeyAccountName(t *testing.T) {
	issuer := "test:accountname"
	key := NewKey(HOTP, "", "")
	// Round #1 return prefix if exist
	key.SetLabel(issuer)
	assert.Equal(t, key.AccountName(), "accountname")

	// Round #2 empty prefix
	key.SetLabel("test")
	assert.Equal(t, key.AccountName(), "")
}

func TestKeyAlgorithm(t *testing.T) {
	key := NewKey(HOTP, "", "")
	// Round #1 -- default digits
	assert.Equal(t, key.Algorithm(), SHA1)

	// Round #2 set digits
	key.SetAlgorithm(SHA512)
	assert.Equal(t, key.Algorithm(), SHA512)
}

func TestKeyPeriod(t *testing.T) {
	key := NewKey(HOTP, "", "")
	key.SetPeriod(60)
	// Round #1 -- 0 poeriod when type HOTP
	assert.Equal(t, key.Period(), uint64(0))

	key = NewKey(TOTP, "", "")
	// Round #2 default period
	assert.Equal(t, key.Period(), uint64(30))

	// Round #3 set period
	key.SetPeriod(60)
	assert.Equal(t, key.Period(), uint64(60))

}

func TestKeyCounter(t *testing.T) {
	key := NewKey(TOTP, "", "")
	key.SetCounter(60)
	// Round #1 -- 0 poeriod when type HOTP
	assert.Equal(t, key.Counter(), uint64(0))

	key = NewKey(HOTP, "", "")
	// Round #2 default period
	assert.Equal(t, key.Counter(), uint64(0))

	// Round #3 set period
	key.SetCounter(60)
	assert.Equal(t, key.Counter(), uint64(60))

}
