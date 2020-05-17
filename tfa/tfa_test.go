package tfa 
import "testing"

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
