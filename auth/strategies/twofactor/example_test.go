package twofactor_test

import (
	"context"
	"fmt"
	"net/http"

	"github.com/shaj13/go-guardian/auth"
	"github.com/shaj13/go-guardian/auth/strategies/basic"
	"github.com/shaj13/go-guardian/auth/strategies/twofactor"
	"github.com/shaj13/go-guardian/otp"
)

type OTPManager struct{}

func (OTPManager) Enabled(_ auth.Info) bool { return true }

func (OTPManager) Load(_ auth.Info) (twofactor.OTP, error) {
	// user otp configuration must be loaded from persistent storage
	key := otp.NewKey(otp.HOTP, "LABEL", "GXNRHI2MFRFWXQGJHWZJFOSYI6E7MEVA")
	ver := otp.New(key)
	return ver, nil
}

func (OTPManager) Store(_ auth.Info, o twofactor.OTP) error {
	// persist user otp after verification
	fmt.Println("Failures: ", o.(*otp.Verifier).Failures)
	return nil
}

func Example() {
	strategy := twofactor.Strategy{
		Parser:  twofactor.XHeaderParser("X-Example-OTP"),
		Manager: OTPManager{},
		Primary: basic.AuthenticateFunc(
			func(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error) {
				return auth.NewDefaultUser("example", "1", nil, nil), nil
			},
		),
	}

	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth("example", "example")
	r.Header.Set("X-Example-OTP", "345515")

	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(info.UserName(), err)

	// Output:
	// Failures:  0
	// example <nil>
}
