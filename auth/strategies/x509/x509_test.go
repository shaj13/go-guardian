package x509

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
			opts := testVerifyOptions(t)

			strategy := New(opts)

			r, _ := http.NewRequest("GET", "/", nil)
			if !tt.insecure {
				r.TLS = &tls.ConnectionState{PeerCertificates: tt.certs}
			}

			info, err := strategy.Authenticate(r.Context(), r)

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

func TestChallenge(t *testing.T) {
	strategy := authenticateFunc(func() x509.VerifyOptions {
		return x509.VerifyOptions{}
	})

	got := strategy.Challenge("Test Realm")
	expected := `X.509 realm="Test Realm", title="Certificate Based Authentication"`

	assert.Equal(t, expected, got)
}

func BenchmarkX509(b *testing.B) {
	opts := testVerifyOptions(b)
	strategy := New(opts)

	r, _ := http.NewRequest("GET", "/", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: readCert(b, "client_valid"),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := strategy.Authenticate(r.Context(), r)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func testVerifyOptions(tb testing.TB) x509.VerifyOptions {
	opts := x509.VerifyOptions{}
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	opts.Roots = x509.NewCertPool()
	opts.Roots.AddCert(readCert(tb, "ca")[0])
	return opts
}

func readCert(tb testing.TB, files ...string) []*x509.Certificate {
	certs := []*x509.Certificate{}

	for _, file := range files {
		file = "testdata/" + file
		data, err := ioutil.ReadFile(file)

		if err != nil {
			tb.Fatalf("error reading %s: %v", file, err)
		}

		p, _ := pem.Decode(data)
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			tb.Fatalf("error parseing certificate %s: %v", file, err)
		}

		if strings.Contains(file, "intermediate") {
			cert.KeyUsage = x509.KeyUsageCertSign
			cert.IsCA = true
		}
		certs = append(certs, cert)
	}

	return certs
}
