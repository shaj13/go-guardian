package x509

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetAllowEmptyCN(t *testing.T) {
	opt := SetAllowEmptyCN()
	s := New(x509.VerifyOptions{}, opt)
	assert.True(t, s.(*strategy).emptyCN)
}

func TestSetAllowedCN(t *testing.T) {
	cns := []string{"a", "b", "c"}
	opt := SetAllowedCN(cns...)
	s := New(x509.VerifyOptions{}, opt)
	for _, cn := range cns {
		assert.True(t, s.(*strategy).allowedCN(cn))
	}
}

func TestSetAllowedCNRegex(t *testing.T) {
	cns := []string{"a", "b", "c"}
	opt := SetAllowedCNRegex("a|b|c")
	s := New(x509.VerifyOptions{}, opt)
	for _, cn := range cns {
		assert.True(t, s.(*strategy).allowedCN(cn))
	}
}
