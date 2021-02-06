package userinfo

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2"
)

func TestSetHTTPMethod(t *testing.T) {
	opt := SetHTTPMethod(http.MethodPost)
	uinfo := newUserInfo("", opt)
	assert.Equal(t, http.MethodPost, uinfo.requester.Method)
}

func TestSetHTTPClient(t *testing.T) {
	client := new(http.Client)
	opt := SetHTTPClient(client)
	uinfo := newUserInfo("", opt)
	assert.Equal(t, client, uinfo.requester.Client)
}

func TestSetTLSConfig(t *testing.T) {
	tls := new(tls.Config)
	opt := SetTLSConfig(tls)
	uinfo := newUserInfo("", opt)
	assert.Equal(t, tls, uinfo.requester.Client.Transport.(*http.Transport).TLSClientConfig)
}

func TestSetClientTransport(t *testing.T) {
	trp := new(http.Transport)
	opt := SetClientTransport(trp)
	uinfo := newUserInfo("", opt)
	assert.Equal(t, trp, uinfo.requester.Client.Transport)
}

func TestSetErrorResolver(t *testing.T) {
	err := oauth2.ResponseError{
		Reason: "test-error",
	}
	opt := SetErrorResolver(err)
	uinfo := newUserInfo("", opt)
	assert.Equal(t, err, uinfo.errorResolver)
}

func TestSetClaimResolver(t *testing.T) {
	claim := Claims{
		Name: "test",
	}
	opt := SetClaimResolver(claim)
	uinfo := newUserInfo("", opt)
	assert.Equal(t, claim, uinfo.claimResolver)
}

func TestSetVerifyOptions(t *testing.T) {
	opts := claims.VerifyOptions{
		Issuer: "test",
	}
	opt := SetVerifyOptions(opts)
	uinfo := newUserInfo("", opt)
	assert.Equal(t, opts, uinfo.opts)
}
