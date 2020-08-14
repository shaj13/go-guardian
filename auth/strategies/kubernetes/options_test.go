package kubernetes

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetServiceAccountToken(t *testing.T) {
	token := "test-token"
	kr := new(kubeReview)
	opt := SetServiceAccountToken(token)
	opt.Apply(kr)
	assert.Equal(t, token, kr.token)
}

func TestSetHTTPClient(t *testing.T) {
	client := new(http.Client)
	kr := new(kubeReview)
	opt := SetHTTPClient(client)
	opt.Apply(kr)
	assert.Equal(t, client, kr.client)
}

func TestSetTLSConfig(t *testing.T) {
	kr := new(kubeReview)
	tls := new(tls.Config)
	kr.client = &http.Client{
		Transport: &http.Transport{},
	}
	opt := SetTLSConfig(tls)
	opt.Apply(kr)
	assert.Equal(t, tls, kr.client.Transport.(*http.Transport).TLSClientConfig)
}

func TestSetClientTransport(t *testing.T) {
	kr := new(kubeReview)
	trp := new(http.Transport)
	kr.client = new(http.Client)
	opt := SetClientTransport(trp)
	opt.Apply(kr)
	assert.Equal(t, trp, kr.client.Transport)
}

func TestSetAddress(t *testing.T) {
	addr := "http://127.0.0.1:8080"
	kr := new(kubeReview)
	opt := SetAddress(addr)
	opt.Apply(kr)
	assert.Equal(t, addr, kr.addr)
}

func TestSetAPIVersion(t *testing.T) {
	ver := "authentication.k8s.io/v1"
	kr := new(kubeReview)
	opt := SetAPIVersion(ver)
	opt.Apply(kr)
	assert.Equal(t, ver, kr.apiVersion)
}

func TestSetAudiences(t *testing.T) {
	aud := []string{"admin", "guest"}
	kr := new(kubeReview)
	opt := SetAudiences(aud)
	opt.Apply(kr)
	assert.Equal(t, aud, kr.audiences)
}
