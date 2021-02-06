package claims

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStringOrListUnmarshalJSON(t *testing.T) {
	table := []struct {
		name      string
		data      string
		expectErr bool
		len       int
	}{
		{
			name:      "it return array when json is array of strings",
			data:      `["1","2"]`,
			expectErr: false,
			len:       2,
		},
		{
			name:      "it return string when json is string",
			data:      `"str"`,
			expectErr: false,
			len:       1,
		},
		{
			name:      "it error when json is not a string or array of strings",
			data:      `{"object":"true"}`,
			expectErr: true,
			len:       0,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			claim := make(StringOrList, 0)
			err := claim.UnmarshalJSON([]byte(tt.data))
			assert.Equal(t, tt.expectErr, err != nil)
			assert.Equal(t, tt.len, len(claim))
		})
	}
}

func TestStringOrListSplit(t *testing.T) {
	table := []struct {
		name     string
		expected []string
		claim    StringOrList
	}{
		{
			name:     "it return claim as is if its from type array",
			expected: []string{"1", "2"},
			claim:    StringOrList{"1", "2"},
		},
		{
			name:     "it split scope by space",
			expected: []string{"openid", "email", "profile"},
			claim:    StringOrList{"openid email profile"},
		},
		{
			name:     "it split claim by comma",
			expected: []string{"openid", "email", "profile"},
			claim:    StringOrList{"openid,email,profile"},
		},
		{
			name:     "it return claim with one element if cant split",
			expected: []string{"openid"},
			claim:    StringOrList{"openid"},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.claim.Split()
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestTime(t *testing.T) {
	toUnix := Time(time.Now())
	fromUnix := new(Time)

	buf, err := toUnix.MarshalJSON()
	assert.NoError(t, err)

	err = fromUnix.UnmarshalJSON(buf)
	assert.NoError(t, err)
	assert.Equal(t, time.Time(toUnix).Unix(), time.Time(*fromUnix).UTC().Unix())
}

func TestVerify(t *testing.T) {
	toTime := func(tt time.Time) *Time {
		t := Time(tt)
		return &t
	}

	table := []struct {
		name  string
		opt   VerifyOptions
		claim Standard
		err   error
	}{
		{
			name: "it return error when claim not yet valid",
			opt:  VerifyOptions{},
			claim: Standard{
				NotBefore: toTime(time.Now().Add(DefaultLeeway * 10)),
			},
			err: InvalidError{Reason: NotBefore},
		},
		{
			name: "it return error when claim has expired",
			opt:  VerifyOptions{},
			claim: Standard{
				ExpiresAt: toTime(time.Now().Add(-DefaultLeeway * 2)),
			},
			err: InvalidError{Reason: Expired},
		},
		{
			name: "it return error when claim issuer name does not match the expected issuer",
			opt: VerifyOptions{
				Issuer: "test.com",
			},
			claim: Standard{
				Issuer: "test",
			},
			err: InvalidError{Reason: IssuerMismatch},
		},
		{
			name: "it return error when claim issued at a future time",
			opt:  VerifyOptions{},
			claim: Standard{
				IssuedAt: toTime(time.Now().Add(DefaultLeeway * 10)),
			},
			err: InvalidError{Reason: IssuedAtFuture},
		},
		{
			name: "it return error when claim  does not have one of the expected audiences",
			opt: VerifyOptions{
				Audience: []string{"test.com"},
			},
			claim: Standard{
				Audience: []string{"test"},
			},
			err: InvalidError{Reason: AudienceNotFound},
		},
		{
			name: "it return nil error when opts is empty",
			opt: VerifyOptions{
				Time: func() (t time.Time) {
					return time.Time{}
				},
			},
			claim: Standard{
				IssuedAt:  toTime(time.Now().Add(DefaultLeeway * 10)),
				ExpiresAt: toTime(time.Now().Add(-(DefaultLeeway * 10))),
				NotBefore: toTime(time.Now().Add(DefaultLeeway * 10)),
				Issuer:    "test",
				Audience:  []string{"test"},
			},
		},
		{
			name: "it return nil error when claim is valid",
			opt: VerifyOptions{
				Audience: []string{"test"},
				Issuer:   "test",
			},
			claim: Standard{
				IssuedAt:  toTime(time.Now().Add(-DefaultLeeway)),
				ExpiresAt: toTime(time.Now().Add(DefaultLeeway * 2)),
				NotBefore: toTime(time.Now().Add(-DefaultLeeway)),
				Issuer:    "test",
				Audience:  []string{"test"},
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claim.Verify(tt.opt)
			if tt.err != nil {
				assert.Equal(t, tt.err.Error(), err.Error())
				return
			}
			assert.NoError(t, err)
		})
	}
}
