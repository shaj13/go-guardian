package digest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParams(t *testing.T) {
	table := []struct {
		name  string
		param string
		value string
	}{
		{
			name:  "it set & get user name",
			param: "username",
			value: "user",
		},
		{
			name:  "it set & get realm",
			param: "realm",
			value: "realm",
		},
		{
			name:  "it set & get uri",
			param: "uri",
			value: "uri",
		},
		{
			name:  "it set & get algorithm",
			param: "algorithm",
			value: "algorithm",
		},
		{
			name:  "it set & get nonce",
			param: "nonce",
			value: "nonce",
		},
		{
			name:  "it set & get cnonce",
			param: "cnonce",
			value: "cnonce",
		},
		{
			name:  "it set & get nc",
			param: "nc",
			value: "nc",
		},
		{
			name:  "it set & get qop",
			param: "qop",
			value: "qop",
		},
		{
			name:  "it set & get response",
			param: "response",
			value: "response",
		},
		{
			name:  "it set & get opaque",
			param: "opaque",
			value: "opaque",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			h := make(Header)
			got := ""

			switch tt.param {
			case "username":
				h.SetUserName(tt.value)
				got = h.UserName()
			case "realm":
				h.SetRealm(tt.value)
				got = h.Realm()
			case "uri":
				h.SetURI(tt.value)
				got = h.URI()
			case "algorithm":
				h.SetAlgorithm(tt.value)
				got = h.Algorithm()
			case "nonce":
				h.SetNonce(tt.value)
				got = h.Nonce()
			case "cnonce":
				h.SetCnonce(tt.value)
				got = h.Cnonce()
			case "nc":
				h.SetNC(tt.value)
				got = h.NC()
			case "qop":
				h.SetQOP(tt.value)
				got = h.QOP()
			case "response":
				h.SetResponse(tt.value)
				got = h.Response()
			case "opaque":
				h.SetOpaque(tt.value)
				got = h.Opaque()
			default:
				t.Errorf("Unsprted param %s", tt.param)
				return
			}

			assert.Equal(t, tt.value, got)

		})
	}
}

func TestParse(t *testing.T) {
	h := make(Header)

	// Round #1
	err := h.Parse("Test")
	assert.EqualError(t, err, ErrInavlidHeader.Error())

	// Round #2
	err = h.Parse(`Digest username="admin", realm="test"`)
	assert.NoError(t, err)
	assert.Equal(t, h.UserName(), "admin")
	assert.Equal(t, h.Realm(), "test")
}

func TestWWWAuthenticateForHeader(t *testing.T) {
	h := make(Header)

	// Round #1
	str, _ := h.WWWAuthenticate()
	assert.Contains(t, str, `qop="auth"`)
	assert.Contains(t, str, "Digest")
	assert.Contains(t, str, "algorithm=")
	assert.Contains(t, str, "opaque=")
	assert.Contains(t, str, "nonce=")
	assert.Contains(t, str, "realm=")

	// Round #2
	h.SetNonce("nounce")
	h.SetOpaque("opaque")
	str, _ = h.WWWAuthenticate()
	assert.Equal(t, str, `Digest realm="", nonce="nounce", opaque="opaque", algorithm=, qop="auth"`)

}
