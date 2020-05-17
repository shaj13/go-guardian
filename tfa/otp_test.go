package tfa

import (
	"strings"
	"testing"
	"time"
)

func TestLockOut(t *testing.T) {
	table := []struct {
		cfg  *OTPConfig
		name string
	}{
		{
			name: "TOTP Lockout",
			cfg: &OTPConfig{
				OTPType:       TOTP,
				MaxAttempts:   4,
				Label:         "Test",
				LockOutDelay:  1,
				EnableLockout: true,
				SecretSize:    20,
			},
		},
		{
			name: "HOTP Lockout",
			cfg: &OTPConfig{
				OTPType:       TOTP,
				MaxAttempts:   4,
				Label:         "Test",
				LockOutDelay:  1,
				EnableLockout: true,
				SecretSize:    20,
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, otp, err := NewOTP(tt.cfg)

			if err != nil {
				t.Fatalf("Unexpected Error for create New OTP, %v", err)
			}

			for i := 1; uint(i) <= (tt.cfg.MaxAttempts * 2); i++ {
				valid, err := otp.Verify("12")

				if valid {
					t.Fatal("Expected Invalid OTP, Got True")
				}

				if uint(i) == tt.cfg.MaxAttempts*2 {
					if err == nil || err.Error() != "Max attempts reached, Account locked out" {
						t.Fatalf("Expected Account to be locked, Attempt %v", i)
					}
					return
				}
				if i%2 == 0 {
					if err == nil || !strings.Contains(err.Error(), "disabled") {
						t.Fatalf("Expected OTP verification Disabled for a period of time, Got %v, Attempt %v", err, i)
					}
					time.Sleep(time.Second * time.Duration(uint(i)))
					continue
				}

				if err != nil {
					t.Fatalf("Unexpeted error %v, Attempt %v", err, i)
				}
			}
		})
	}
}

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

	if len(cfg.Secret) == 0 {
		t.Errorf("Expected Secret to be generated, Got %s", cfg.Secret)
	}

	if cfg.Digits != SixDigits {
		t.Errorf("Expected Digits as default to be 6, Got %s", cfg.Digits)
	}

	if cfg.HashAlgorithm != SHA1 {
		t.Errorf("Expected HashAlgorithm as default to be SHA1, Got %s", cfg.HashAlgorithm)
	}

	if cfg.MaxAttempts != 3 {
		t.Errorf("Expected MaxAttempts as default to be 3, Got %v", cfg.MaxAttempts)
	}

	if cfg.LockOutDelay != 30 {
		t.Errorf("Expected LockOutDelay as default to be 30, Got %v", cfg.LockOutDelay)
	}

	if cfg.Period != 30 {
		t.Errorf("Expected Period as default to be 30, Got %v", cfg.Period)
	}
}
