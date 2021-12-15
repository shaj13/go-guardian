package jwt

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/m87carlson/go-guardian/v2/auth/claims"
)

func TestSetHTTPClient(t *testing.T) {
	client := new(http.Client)
	opt := SetHTTPClient(client)
	s := newStrategy("", opt)
	assert.Equal(t, client, s.jwks.requester.Client)
}

func TestSetTLSConfig(t *testing.T) {
	tls := new(tls.Config)
	opt := SetTLSConfig(tls)
	s := newStrategy("", opt)
	assert.Equal(t, tls, s.jwks.requester.Client.Transport.(*http.Transport).TLSClientConfig)
}

func TestSetClientTransport(t *testing.T) {
	trp := new(http.Transport)
	opt := SetClientTransport(trp)
	s := newStrategy("", opt)
	assert.Equal(t, trp, s.jwks.requester.Client.Transport)
}

func TestSetInterval(t *testing.T) {
	opt := SetInterval(time.Hour)
	s := newStrategy("", opt)
	assert.Equal(t, time.Hour, s.jwks.interval)
}

func TestSetClaimResolver(t *testing.T) {
	opt := SetClaimResolver(nil)
	s := newStrategy("", opt)
	assert.Equal(t, nil, s.claimResolver)
}

func TestSetVerifyOptions(t *testing.T) {
	opts := claims.VerifyOptions{
		Issuer: "test",
	}
	opt := SetVerifyOptions(opts)
	s := newStrategy("", opt)
	assert.Equal(t, opts, s.opts)
}
