package x509

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"testing"

	"github.com/shaj13/go-guardian/auth"
)

func Example() {
	opts := x509.VerifyOptions{}
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	opts.Roots = x509.NewCertPool()
	// Read Root Ca Certificate
	opts.Roots.AddCert(readCertificates("ca")[0])

	// create strategy and authenticator
	strategy := New(opts)
	authenticator := auth.New()
	authenticator.EnableStrategy(StrategyKey, strategy)

	// user request
	req, _ := http.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: readCertificates("client_valid")}

	// validate request
	info, err := authenticator.Authenticate(req)
	fmt.Println(info.UserName(), err)

	// validate expired client certificate
	req.TLS = &tls.ConnectionState{PeerCertificates: readCertificates("client_expired")}
	info, err = authenticator.Authenticate(req)
	fmt.Println(info, err.(auth.Error).Errors()[1])

	// Output:
	// host.test.com <nil>
	// <nil> x509: certificate has expired or is not yet valid
}

func ExampleInfoBuilder() {
	opts := x509.VerifyOptions{}
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	opts.Roots = x509.NewCertPool()
	// Read Root Ca Certificate
	opts.Roots.AddCert(readCertificates("ca")[0])

	// create strategy and authenticator
	strategy := New(opts)
	Builder = InfoBuilder(func(chain [][]*x509.Certificate) (auth.Info, error) {
		return auth.NewDefaultUser("user-info-builder", "10", nil, nil), nil
	})
	authenticator := auth.New()
	authenticator.EnableStrategy(StrategyKey, strategy)

	// user request
	req, _ := http.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: readCertificates("client_valid")}

	// validate request
	info, err := authenticator.Authenticate(req)
	fmt.Println(info.UserName(), err)

	// Output:
	// user-info-builder <nil>
}

func readCertificates(cert string) []*x509.Certificate {
	return readCert(new(testing.T), cert)
}
