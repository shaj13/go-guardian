// Package x509 provides authentication strategy,
// to authenticate HTTPS requests and builds, extracts user informations from client certificates.
package x509

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/m87carlson/go-guardian/v2/auth"
)

var (
	// ErrInvalidRequest is returned by x509 strategy when a non TLS request received.
	ErrInvalidRequest = errors.New("strategy/x509: Invalid request, missing TLS parameters")

	// ErrMissingCN is returned by DefaultBuilder when Certificate CommonName missing.
	ErrMissingCN = errors.New("strategies/x509: Certificate subject CN missing")
)

// InfoBuilder declare a function signature for building Info from certificate chain.
type InfoBuilder func(chain [][]*x509.Certificate) (auth.Info, error)

// New returns auth.Strategy authenticate request from client certificates
func New(vopt x509.VerifyOptions, opts ...auth.Option) auth.Strategy {
	s := new(strategy)
	s.fn = func() x509.VerifyOptions { return vopt }
	s.builder = infoBuilder
	s.allowedCN = func(string) bool { return true }
	for _, opt := range opts {
		opt.Apply(s)
	}
	return s
}

type strategy struct {
	fn        func() x509.VerifyOptions
	builder   InfoBuilder
	emptyCN   bool
	allowedCN func(string) bool
}

func (s strategy) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {

	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, ErrInvalidRequest
	}

	// get verify options shallow copy
	opts := s.fn()

	// copy intermediates certificates to verify options from request if needed.
	// ignore r.TLS.PeerCertificates[0] it refer to client certificates.
	if opts.Intermediates == nil && len(r.TLS.PeerCertificates) > 1 {
		opts.Intermediates = x509.NewCertPool()
		for _, inter := range r.TLS.PeerCertificates[1:] {
			opts.Intermediates.AddCert(inter)
		}
	}

	chain, err := r.TLS.PeerCertificates[0].Verify(opts)

	if err != nil {
		return nil, err
	}

	return s.build(chain)
}

func (s strategy) build(chain [][]*x509.Certificate) (auth.Info, error) {
	cn := chain[0][0].Subject.CommonName

	if len(cn) == 0 && !s.emptyCN {
		return nil, ErrMissingCN
	}

	if !s.allowedCN(cn) {
		return nil, fmt.Errorf("strategies/x509: Certificate subject %s CN is not allowed", cn)
	}

	return s.builder(chain)
}

// infoBuilder define default InfoBuilder by building Info from certificate chain subject.
func infoBuilder(chain [][]*x509.Certificate) (auth.Info, error) {
	subject := chain[0][0].Subject

	exts := map[string][]string{
		"country":       subject.Country,
		"postalCode":    subject.PostalCode,
		"streetAddress": subject.StreetAddress,
		"locality":      subject.Locality,
		"province":      subject.Province,
	}

	return auth.NewUserInfo(
		subject.CommonName,
		subject.SerialNumber,
		subject.Organization,
		exts,
	), nil
}
