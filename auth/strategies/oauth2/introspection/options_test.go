package introspection

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2"
)

func TestSetAuthorizationToken(t *testing.T) {
	token := "test-token"
	opt := SetAuthorizationToken(token)
	intro := newIntrospection("", opt)
	r, _ := http.NewRequest("", "", nil)
	intro.requester.AdditionalData(r)
	assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
	assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
	assert.Equal(t, "application/json", r.Header.Get("Accept"))
}

func TestSetBasicAuth(t *testing.T) {
	id := "client-id"
	secret := "client-secret"
	opt := SetBasicAuth(id, secret)
	intro := newIntrospection("", opt)
	r, _ := http.NewRequest("", "", nil)
	intro.requester.AdditionalData(r)
	gotid, gotsecret, _ := r.BasicAuth()
	assert.Equal(t, id, gotid)
	assert.Equal(t, secret, gotsecret)
	assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
	assert.Equal(t, "application/json", r.Header.Get("Accept"))
}

func TestSetHTTPClient(t *testing.T) {
	client := new(http.Client)
	opt := SetHTTPClient(client)
	intro := newIntrospection("", opt)
	assert.Equal(t, client, intro.requester.Client)
}

func TestSetTLSConfig(t *testing.T) {
	tls := new(tls.Config)
	opt := SetTLSConfig(tls)
	intro := newIntrospection("", opt)
	assert.Equal(t, tls, intro.requester.Client.Transport.(*http.Transport).TLSClientConfig)
}

func TestSetClientTransport(t *testing.T) {
	trp := new(http.Transport)
	opt := SetClientTransport(trp)
	intro := newIntrospection("", opt)
	assert.Equal(t, trp, intro.requester.Client.Transport)
}

func TestSetErrorResolver(t *testing.T) {
	err := oauth2.ResponseError{
		Reason: "test-error",
	}
	opt := SetErrorResolver(err)
	intro := newIntrospection("", opt)
	assert.Equal(t, err, intro.errorResolver)
}

func TestSetClaimResolver(t *testing.T) {
	claim := Claims{
		UserName: "test-error",
	}
	opt := SetClaimResolver(claim)
	intro := newIntrospection("", opt)
	assert.Equal(t, claim, intro.claimResolver)
}

func TestSetVerifyOptions(t *testing.T) {
	opts := claims.VerifyOptions{
		Issuer: "test",
	}
	opt := SetVerifyOptions(opts)
	intro := newIntrospection("", opt)
	assert.Equal(t, opts, intro.opts)
}
