package kubernetes

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetServiceAccountToken(t *testing.T) {
	appj := "application/json"
	token := "test-token"
	opt := SetServiceAccountToken(token)
	kr := newKubeReview(opt)
	r, _ := http.NewRequest("", "", nil)
	kr.requester.AdditionalData(r)
	assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
	assert.Equal(t, appj, r.Header.Get("Content-Type"))
	assert.Equal(t, appj, r.Header.Get("Accept"))
}

func TestSetHTTPClient(t *testing.T) {
	client := new(http.Client)
	opt := SetHTTPClient(client)
	kr := newKubeReview(opt)
	assert.Equal(t, client, kr.requester.Client)
}

func TestSetTLSConfig(t *testing.T) {
	tls := new(tls.Config)
	opt := SetTLSConfig(tls)
	kr := newKubeReview(opt)
	assert.Equal(t, tls, kr.requester.Client.Transport.(*http.Transport).TLSClientConfig)
}

func TestSetClientTransport(t *testing.T) {
	trp := new(http.Transport)
	opt := SetClientTransport(trp)
	kr := newKubeReview(opt)
	assert.Equal(t, trp, kr.requester.Client.Transport)
}

func TestSetAddress(t *testing.T) {
	addr := "http://127.0.0.1:8080/"
	opt := SetAddress(addr)
	kr := newKubeReview(opt)
	assert.Equal(t, addr[:len(addr)-1], kr.requester.Addr)
}

func TestSetAPIVersion(t *testing.T) {
	ver := "authentication.k8s.io/v1"
	opt := SetAPIVersion(ver)
	kr := newKubeReview(opt)
	assert.Contains(t, kr.requester.Endpoint, ver)
}

func TestSetAudiences(t *testing.T) {
	aud := []string{"admin", "guest"}
	kr := new(kubeReview)
	opt := SetAudiences(aud)
	opt.Apply(kr)
	assert.Equal(t, aud, kr.audiences)
}
