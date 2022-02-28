package x509_test

import (
	"crypto/tls"
	crypto_x509 "crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/x509"
)

const (
	valid = `
-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIUVKhnHkYcQpTnR4OAdSe1uSzcwaEwDQYJKoZIhvcNAQEL
BQAwbTELMAkGA1UEBhMCR0IxEDAOBgNVBAgTB0VuZ2xhbmQxDzANBgNVBAcTBkxv
bmRvbjENMAsGA1UEChMEVEVTVDEVMBMGA1UECxMMVEVTVCBSb290IENBMRUwEwYD
VQQDEwxURVNUIFJvb3QgQ0EwHhcNMjIwMjI4MDkyNzAwWhcNMjMwMjI4MDkyNzAw
WjBsMQswCQYDVQQGEwJHQjEQMA4GA1UECBMHRW5nbGFuZDEPMA0GA1UEBxMGTG9u
ZG9uMQ0wCwYDVQQKEwRUZXN0MRMwEQYDVQQLEwpUZXN0IEhvc3RzMRYwFAYDVQQD
Ew1ob3N0LnRlc3QuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
rtweyLzSlapYr11gQ+C14N1Z2kYhYhaIHBd6xXDlQp0K25E9NSWh68ZdtDbon9MG
no9K6/BbO8SAehwum2RTXGUPkvcH9uDTMKgLu6kYJd9Qu8DoC3iEDM9cQqg05Qjg
mBsvTkiSIBg68piKHIVjD6iH2572+QjEwF5SB0N3mKmad2n8F5BHpAxoIAENlpt2
lnrQ1UwJnmkBbA1HYVAovN9Zwiu7Y9cDWBrtDLLhgcFBCJSTK81rbf40+KRrQ4cL
dI2k7J1APRY111MdjsC/1NqBOqTtYs4gvanjFWzRaDn63ZNgCv+qYuyb0o02c10c
SNbL56DLG1nlQqsDZQ5ApwIDAQABo4GcMIGZMA4GA1UdDwEB/wQEAwIFoDATBgNV
HSUEDDAKBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRiUsvADnef
EURF7H9mEpqp0CqITTAfBgNVHSMEGDAWgBQS+MWiDBJ/RSBG5NR+tMuE8IJoHTAk
BgNVHREEHTAbgg5ob3N0MS50ZXN0LmNvbYIJbG9jYWxob3N0MA0GCSqGSIb3DQEB
CwUAA4IBAQAEcPZ5zwS3WrsxvwicOMrvM9rNYRlKhEgtUpSZ41RN6WnJVUosrmeG
SaGui45FjiemaTyMRS+q0OEpzV55Hzs9KatUv8B7TpMZdfsjGl8D2FPJxOJ4nMLk
CdLOmIctwDmw0eZ7w6sis4bKLaeOy1V7ZD7S7U1SdHK7583PTtYoYlAAmvrnwFf7
VICP5QyFZLtdZmiSOSFmgTprEbkOGBcprlMgI8FQBnNZDFVO1v95mU7ibNCAfE6h
qGsVI3PWEk2i9qW0Gwh/koqlz02AvTtBI7o9ILo3D0kx/0R5K7Gqbyye1k8bcEdh
3oJA9wYPZ7vWY6dFGODY8djAC78wLVsq
-----END CERTIFICATE-----	
	`

	expired = `
-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIUCQhmpjO4Vmxhv7qY00uv3TrZESIwDQYJKoZIhvcNAQEL
BQAwbTELMAkGA1UEBhMCR0IxEDAOBgNVBAgTB0VuZ2xhbmQxDzANBgNVBAcTBkxv
bmRvbjENMAsGA1UEChMEVEVTVDEVMBMGA1UECxMMVEVTVCBSb290IENBMRUwEwYD
VQQDEwxURVNUIFJvb3QgQ0EwHhcNMTkxMjMxMjM1OTAwWhcNMTkxMjMxMjM1OTAw
WjBsMQswCQYDVQQGEwJHQjEQMA4GA1UECBMHRW5nbGFuZDEPMA0GA1UEBxMGTG9u
ZG9uMQ0wCwYDVQQKEwRUZXN0MRMwEQYDVQQLEwpUZXN0IEhvc3RzMRYwFAYDVQQD
Ew1ob3N0LnRlc3QuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
rtweyLzSlapYr11gQ+C14N1Z2kYhYhaIHBd6xXDlQp0K25E9NSWh68ZdtDbon9MG
no9K6/BbO8SAehwum2RTXGUPkvcH9uDTMKgLu6kYJd9Qu8DoC3iEDM9cQqg05Qjg
mBsvTkiSIBg68piKHIVjD6iH2572+QjEwF5SB0N3mKmad2n8F5BHpAxoIAENlpt2
lnrQ1UwJnmkBbA1HYVAovN9Zwiu7Y9cDWBrtDLLhgcFBCJSTK81rbf40+KRrQ4cL
dI2k7J1APRY111MdjsC/1NqBOqTtYs4gvanjFWzRaDn63ZNgCv+qYuyb0o02c10c
SNbL56DLG1nlQqsDZQ5ApwIDAQABo4GcMIGZMA4GA1UdDwEB/wQEAwIFoDATBgNV
HSUEDDAKBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRiUsvADnef
EURF7H9mEpqp0CqITTAfBgNVHSMEGDAWgBQS+MWiDBJ/RSBG5NR+tMuE8IJoHTAk
BgNVHREEHTAbgg5ob3N0MS50ZXN0LmNvbYIJbG9jYWxob3N0MA0GCSqGSIb3DQEB
CwUAA4IBAQCHJyYJOqm29SptDu9V/dF1ZAjkBbXQ3obxYnxGsHnl4YU0ETdRQvdV
j73XGuTY8Na2n4EV9fHOabzlF5TJGWJJmv6hOCQjNXjEewN2OPyXxffnQxwz4Pid
w//AZyO5ylmWo3jboqjBZzL14B4MVIYa1L8APNY95MZAy6FgG/+JukyAS2GPm46H
DRktsrz/IRB/nqbnf+0PImTnixwZUzMHVDYLMtMpFifw9M7W/ZXK4Zd+TcT7Kvge
58f/qOvo5TlXgsp2xvyDajLyqNluRCz8Q/EYsTK+2D/iWvbWRXetPjuC9rBCVoLc
7ORcnSL/gPdPUO3W47fHHaBA/usXObv/
-----END CERTIFICATE-----
	`

	ca = `
-----BEGIN CERTIFICATE-----
MIIDqjCCApKgAwIBAgIUQgSrqSXHbP8ljn7Bp9W6yoDF6ZcwDQYJKoZIhvcNAQEL
BQAwbTELMAkGA1UEBhMCR0IxEDAOBgNVBAgTB0VuZ2xhbmQxDzANBgNVBAcTBkxv
bmRvbjENMAsGA1UEChMEVEVTVDEVMBMGA1UECxMMVEVTVCBSb290IENBMRUwEwYD
VQQDEwxURVNUIFJvb3QgQ0EwHhcNMjIwMjI4MDkyNzAwWhcNMjcwMjI3MDkyNzAw
WjBtMQswCQYDVQQGEwJHQjEQMA4GA1UECBMHRW5nbGFuZDEPMA0GA1UEBxMGTG9u
ZG9uMQ0wCwYDVQQKEwRURVNUMRUwEwYDVQQLEwxURVNUIFJvb3QgQ0ExFTATBgNV
BAMTDFRFU1QgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AKDuK1yk668L20Depz7vV7pgGR09AqYVBTWElNDxRKPXdILf7//zq37dzeIxktNy
MvaCukQ7l+nvNsexQWqWf6rIRbexQwUwUDpFCmuXAbBL9/9Wvz4xeIJPkhF1Eigd
dhQ5M9/omHnP9LVR3/ei/DZoFs3tPegvdI9bxOKonnUJfFfloF/HGsbO1M5LEZL5
vIbRLdnkmaxB6DqfeH9/La/gHxFRFQGxozBl+/1H71DL81tk93ERQ8v4Sbhw/brW
lG1Dsdf8BivM2E6Vpef0CMKM+SinxSpDUDoWX+ZcU5nFt2QRsXV2SBKGJsO2WyqS
2hg7Ig748Lp9EzEQtg0ZX40CAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1Ud
EwEB/wQFMAMBAf8wHQYDVR0OBBYEFBL4xaIMEn9FIEbk1H60y4TwgmgdMA0GCSqG
SIb3DQEBCwUAA4IBAQA1ripZ3A8plG06QU619d21LlS7IyAn13owCHyeXwynQpWB
XI68MLoxA05mizzLi/p6+LDW2t/nXjDIj+y72lt1jkNYFTC38xP7xViQPsGSEAlL
W+rxTZPy+0ol3iM5FHf+h0Ivr2xXc4FsxIaeCkbjk0vHsu3u6KCL6JXmlo5SuTgV
ypDOW9M1+Dj7EIdpNgQhbaAjQ4S/I+g2pH89fa5SlV+kO+lwq+jrNkjctpX2kOVc
T78nh0o20v9Yz5MEyNbsGhBZulANFRC0XGq/APQG3naQpMTP9LgrdnNrBtIwruFu
kGESrcNRKbsfioRyS45KHwgkLF8ycInYrHmm6cKV
-----END CERTIFICATE-----	
	`
)

func Example() {
	opts := CreateVerifyOptions()
	// create strategy and authenticator
	strategy := x509.New(opts)

	// user request
	req, _ := http.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*crypto_x509.Certificate{ParseCertificate(valid)}}

	// validate request
	info, err := strategy.Authenticate(req.Context(), req)
	fmt.Println(info.GetUserName(), err)

	// validate expired client certificate
	req.TLS = &tls.ConnectionState{PeerCertificates: []*crypto_x509.Certificate{ParseCertificate(expired)}}
	info, err = strategy.Authenticate(req.Context(), req)
	fmt.Println(info, err != nil)

	// Output:
	// host.test.com <nil>
	// <nil> true
}

func ExampleInfoBuilder() {
	opts := CreateVerifyOptions()
	builder := x509.SetInfoBuilder(func(chain [][]*crypto_x509.Certificate) (auth.Info, error) {
		return auth.NewDefaultUser("user-info-builder", "10", nil, nil), nil
	})

	// create strategy and authenticator
	strategy := x509.New(opts, builder)

	// user request
	req, _ := http.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*crypto_x509.Certificate{ParseCertificate(valid)}}

	// validate request
	info, err := strategy.Authenticate(req.Context(), req)
	fmt.Println(info.GetUserName(), err)

	// Output:
	// user-info-builder <nil>
}

func ExampleSetAllowedCN() {
	opts := CreateVerifyOptions()
	cn := x509.SetAllowedCN("1st.cn", "2nd.cn")
	// create strategy and authenticator
	strategy := x509.New(opts, cn)

	// user request
	req, _ := http.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*crypto_x509.Certificate{ParseCertificate(valid)}}

	// validate request
	_, err := strategy.Authenticate(req.Context(), req)
	fmt.Println(err)

	// Output:
	// strategies/x509: Certificate subject host.test.com CN is not allowed
}

func ExampleSetAllowedCNRegex() {
	opts := CreateVerifyOptions()
	cn := x509.SetAllowedCNRegex("(host.*.org)")
	// create strategy and authenticator
	strategy := x509.New(opts, cn)

	// user request
	req, _ := http.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*crypto_x509.Certificate{ParseCertificate(valid)}}

	// validate request
	_, err := strategy.Authenticate(req.Context(), req)
	fmt.Println(err)

	// Output:
	// strategies/x509: Certificate subject host.test.com CN is not allowed
}

func ParseCertificate(str string) *crypto_x509.Certificate {
	p, _ := pem.Decode([]byte(str))
	if p == nil {
		fmt.Println("Failed to decode certificate")
		return nil
	}
	cert, err := crypto_x509.ParseCertificate(p.Bytes)
	if err != nil {
		fmt.Println(err)
	}
	return cert
}

func CreateVerifyOptions() crypto_x509.VerifyOptions {
	opts := crypto_x509.VerifyOptions{}
	opts.KeyUsages = []crypto_x509.ExtKeyUsage{crypto_x509.ExtKeyUsageClientAuth}
	opts.Roots = crypto_x509.NewCertPool()
	// Read Root Ca Certificate
	opts.Roots.AddCert(ParseCertificate(ca))
	return opts
}
