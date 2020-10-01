package twofactor

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/shaj13/go-guardian/v2/auth"
)

func TestStrategy(t *testing.T) {
	table := []struct {
		name         string
		err          error
		pin          string
		expectedInfo bool
		prepare      func(t *testing.T) TwoFactor
	}{
		{
			name: "it return error when primary strategy return error",
			err:  fmt.Errorf("primary strategy error"),
			prepare: func(t *testing.T) TwoFactor {
				m := &mockStrategy{mock.Mock{}}
				m.
					On("Authenticate").
					Return(nil, fmt.Errorf("primary strategy error"))
				return TwoFactor{Primary: m}
			},
		},
		{
			name:         "it return info when user does not enabled tfa",
			err:          nil,
			expectedInfo: true,
			prepare: func(t *testing.T) TwoFactor {
				m := &mockStrategy{mock.Mock{}}
				m.On("Authenticate").Return(nil, nil)

				mng := &mockManager{mock.Mock{}}
				mng.On("Enabled").Return(false)

				return TwoFactor{Primary: m, Manager: mng}
			},
		},
		{
			name: "it return error when pin missing",
			err:  ErrMissingOTP,
			prepare: func(t *testing.T) TwoFactor {
				m := &mockStrategy{mock.Mock{}}
				m.On("Authenticate").Return(nil, nil)

				mng := &mockManager{mock.Mock{}}
				mng.On("Enabled").Return(true)

				return TwoFactor{Primary: m, Manager: mng}
			},
		},
		{
			name: "it return error when manager load return error",
			err:  fmt.Errorf("manager load error"),
			pin:  "123456",
			prepare: func(t *testing.T) TwoFactor {
				m := &mockStrategy{mock.Mock{}}
				m.On("Authenticate").Return(nil, nil)

				mng := &mockManager{mock.Mock{}}
				mng.On("Enabled").Return(true)
				mng.On("Load").Return(new(mockOTP), fmt.Errorf("manager load error"))

				return TwoFactor{Primary: m, Manager: mng}
			},
		},
		{
			name: "it return error when otp Verify return error",
			err:  fmt.Errorf("OTP Error"),
			pin:  "123456",
			prepare: func(t *testing.T) TwoFactor {
				m := &mockStrategy{mock.Mock{}}
				m.On("Authenticate").Return(nil, nil)

				otp := &mockOTP{mock.Mock{}}
				otp.On("Verify").Return(false, fmt.Errorf("OTP Error"))

				mng := &mockManager{mock.Mock{}}
				mng.On("Enabled").Return(true)
				mng.On("Load").Return(otp, nil)
				mng.On("Store").Return(nil)

				return TwoFactor{Primary: m, Manager: mng}
			},
		},
		{
			name: "it return error when otp Verify return false",
			err:  ErrInvalidOTP,
			pin:  "123456",
			prepare: func(t *testing.T) TwoFactor {
				m := &mockStrategy{mock.Mock{}}
				m.On("Authenticate").Return(nil, nil)

				otp := &mockOTP{mock.Mock{}}
				otp.On("Verify").Return(false, nil)

				mng := &mockManager{mock.Mock{}}
				mng.On("Enabled").Return(true)
				mng.On("Load").Return(otp, nil)
				mng.On("Store").Return(nil)

				return TwoFactor{Primary: m, Manager: mng}
			},
		},
		{
			name:         "it return info when user authenticated",
			err:          nil,
			pin:          "123456",
			expectedInfo: true,
			prepare: func(t *testing.T) TwoFactor {
				m := &mockStrategy{mock.Mock{}}
				m.On("Authenticate").Return(nil, nil)

				otp := &mockOTP{mock.Mock{}}
				otp.On("Verify").Return(true, nil)

				mng := &mockManager{mock.Mock{}}
				mng.On("Enabled").Return(true)
				mng.On("Load").Return(otp, nil)
				mng.On("Store").Return(nil)

				return TwoFactor{Primary: m, Manager: mng}
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.prepare(t)
			s.Parser = XHeaderParser("X-TEST-OTP")
			r, _ := http.NewRequest("GET", "/", nil)
			r.Header.Set("X-TEST-OTP", tt.pin)
			info, err := s.Authenticate(r.Context(), r)
			assert.Equal(t, tt.err, err)
			assert.Equal(t, tt.expectedInfo, info != nil)
		})
	}
}

// ----------------------------------------------------------------------------
// Test factories
// ----------------------------------------------------------------------------

type mockStrategy struct {
	mock.Mock
}

func (m *mockStrategy) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	args := m.Called()
	return auth.NewDefaultUser("", "", nil, nil), args.Error(1)
}

type mockManager struct {
	mock.Mock
}

func (m *mockManager) Enabled(user auth.Info) bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *mockManager) Load(user auth.Info) (Verifier, error) {
	args := m.Called()
	return args.Get(0).(Verifier), args.Error(1)
}

func (m *mockManager) Store(user auth.Info, otp Verifier) error {
	args := m.Called()
	return args.Error(0)
}

type mockOTP struct {
	mock.Mock
}

func (m *mockOTP) Verify(pin string) (bool, error) {
	args := m.Called()
	return args.Bool(0), args.Error(1)
}
