package x509

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

func Test(t *testing.T) {
	table := []struct {
		name        string
		certs       []*x509.Certificate
		insecure    bool
		expectedErr bool
	}{
		{
			name:        "valid client certificate",
			certs:       readCert(t, "client_valid"),
			insecure:    false,
			expectedErr: false,
		},
		{
			name:        "expired client certificate",
			certs:       readCert(t, "client_expired"),
			insecure:    false,
			expectedErr: true,
		},
		{
			name:        "future client certificate",
			certs:       readCert(t, "client_future"),
			insecure:    false,
			expectedErr: true,
		},
		{
			name:        "future client certificate using intermediate",
			certs:       readCert(t, "client_intermediate_future", "intermediate"),
			insecure:    false,
			expectedErr: true,
		},
		{
			name:        "expired client certificate using intermediate",
			certs:       readCert(t, "client_intermediate_expired", "intermediate"),
			insecure:    false,
			expectedErr: true,
		},
		{
			name:        "valid client certificate using intermediate",
			certs:       readCert(t, "client_intermediate_valid", "intermediate"),
			insecure:    false,
			expectedErr: false,
		},
		{
			name:        "non tls request",
			insecure:    true,
			expectedErr: true,
		},
		{
			name:        "non tls request -- peer certs zero length",
			insecure:    false,
			certs:       []*x509.Certificate{},
			expectedErr: true,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			opts := x509.VerifyOptions{}
			opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			opts.Roots = x509.NewCertPool()
			opts.Roots.AddCert(readCert(t, "ca")[0])

			strat := New(opts)

			r, _ := http.NewRequest("GET", "/", nil)
			if !tt.insecure {
				r.TLS = &tls.ConnectionState{PeerCertificates: tt.certs}
			}

			info, err := strat.Authenticate(r.Context(), r)

			if tt.expectedErr && err == nil {
				t.Errorf("%s: Expected error, got none", tt.name)
				return
			}

			if !tt.expectedErr && err != nil {
				t.Errorf("%s: Got unexpected error: %v", tt.name, err)
				return
			}

			if !tt.expectedErr && info == nil {
				t.Errorf("%s: Expected info object, got nil: %v", tt.name, err)
				return
			}
		})
	}
}

func readCert(t *testing.T, files ...string) []*x509.Certificate {
	certs := []*x509.Certificate{}

	for _, file := range files {
		file = "testdata/" + file
		data, err := ioutil.ReadFile(file)

		if err != nil {
			t.Fatalf("error reading %s: %v", file, err)
		}

		p, _ := pem.Decode(data)
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			t.Fatalf("error parseing certificate %s: %v", file, err)
		}

		if strings.Contains(file, "intermediate") {
			cert.KeyUsage = x509.KeyUsageCertSign
			cert.IsCA = true
		}
		certs = append(certs, cert)
	}

	return certs
}
