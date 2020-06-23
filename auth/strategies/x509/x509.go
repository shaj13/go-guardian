// Package x509 provides authentication strategy,
// to authenticate HTTPS requests and builds, extracts user informations from client certificates.
package x509

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/shaj13/go-guardian/auth"
)

// StrategyKey export identifier for the x509 strategy,
// commonly used when enable/add strategy to go-guardian authenticator.
const StrategyKey = auth.StrategyKey("x509.Strategy")

var (
	// ErrMissingCN is returned by DefaultBuilder when Certificate CommonName missing.
	ErrMissingCN = errors.New("x509.strategy: Certificate subject CN missing")
	// ErrInvalidRequest is returned by x509 strategy when a non TLS request received.
	ErrInvalidRequest = errors.New("x509.strategy: Invalid request, missing TLS parameters")
)

// InfoBuilder declare a function signature for building Info from certificate chain.
type InfoBuilder func(chain [][]*x509.Certificate) (auth.Info, error)

// Builder define default InfoBuilder by building Info from certificate chain subject.
// where the subject values mapped  in the following format,
// CommonName to UserName, SerialNumber to ID, Organization to groups
// and country, postalCode, streetAddress, locality, province mapped to Extensions.
var Builder = InfoBuilder(func(chain [][]*x509.Certificate) (auth.Info, error) {
	subject := chain[0][0].Subject

	if len(subject.CommonName) == 0 {
		return nil, ErrMissingCN
	}

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
})

type authenticateFunc func() x509.VerifyOptions

func (f authenticateFunc) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {

	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, ErrInvalidRequest
	}

	// get verify options shallow copy
	opts := f()

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

	return Builder(chain)
}

// New returns auth.Strategy authenticate request from client certificates
func New(opts x509.VerifyOptions) auth.Strategy {
	return authenticateFunc(func() x509.VerifyOptions { return opts })
}
