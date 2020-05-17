package tfa

import (
	"fmt"
	"time"
)

func ExampleNewOTP() {
	cfg := &OTPConfig{
		OTPType:    TOTP,
		Label:      "Test",
		SecretSize: 20,
	}
	_, otp, _ := NewOTP(cfg)
	ok, err := otp.Verify("123456")
	fmt.Println(ok, err)
	// Output:
	// false <nil>
}

func ExampleNewOTP_second() {
	cfg := &OTPConfig{
		OTPType:    HOTP,
		Label:      "Test",
		Secret:     "GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA",
		SecretSize: 20,
	}
	_, otp, _ := NewOTP(cfg)
	ok, err := otp.Verify("345515") // counter 0
	fmt.Println(ok, err)
	ok, err = otp.Verify("422283") // counter 1
	fmt.Println(ok, err)
	// Output:
	// true <nil>
}

func ExampleNewOTP_third() {
	cfg := &OTPConfig{
		OTPType:       HOTP,
		MaxAttempts:   1,
		Label:         "Test",
		Secret:        "GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA",
		LockOutDelay:  1,
		EnableLockout: true,
		SecretSize:    20,
	}
	_, otp, _ := NewOTP(cfg)
	ok, err := otp.Verify("1234567") // counter 0
	fmt.Println(ok, err)
	time.Sleep(time.Second)
	ok, err = otp.Verify("12345678") // counter 1
	fmt.Println(ok, err)
	// Output:
	// false <nil>
	// false Max attempts reached, Account locked out
}

func ExampleNewOTPFromKey() {
	key, otp, _ := NewOTPFromKey("otpauth://hotp/TEST?secret=GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA")
	ok, err := otp.Verify("345515") // counter 0
	fmt.Println(ok, err)
	fmt.Println(key.Digits())
	fmt.Println(key.Type())
	fmt.Println(key.Secret())
	fmt.Println(key.Label())
	// Output:
	// true <nil>
	// 6
	// hotp
	// GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA
	// TEST
}
