package otp_test

import (
	"fmt"

	"github.com/shaj13/go-guardian/v2/otp"
)

func Example() {
	key, _ := otp.NewKeyFromRaw("otpauth://hotp/TEST?secret=GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA")
	verifier := otp.New(key)
	ok, err := verifier.Verify("345515")
	fmt.Println(ok, err)
	// Output:
	// true <nil>
}
