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
MIIEBDCCAuygAwIBAgIUDJgNc70lDeFv6f7B2Mwy9WEcK9QwDQYJKoZIhvcNAQEL
BQAwbTELMAkGA1UEBhMCR0IxEDAOBgNVBAgTB0VuZ2xhbmQxDzANBgNVBAcTBkxv
bmRvbjENMAsGA1UEChMEVEVTVDEVMBMGA1UECxMMVEVTVCBSb290IENBMRUwEwYD
VQQDEwxURVNUIFJvb3QgQ0EwHhcNMjAwNTEzMTI0MjAwWhcNMjEwNTEzMTI0MjAw
WjBsMQswCQYDVQQGEwJHQjEQMA4GA1UECBMHRW5nbGFuZDEPMA0GA1UEBxMGTG9u
ZG9uMQ0wCwYDVQQKEwRUZXN0MRMwEQYDVQQLEwpUZXN0IEhvc3RzMRYwFAYDVQQD
Ew1ob3N0LnRlc3QuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
oDiZOcVxTxOFZIwIAAjHsyXqTz3Hht5iySMyDbApw6C6aHHWVBur1uUnhTh8ek7f
8DbLZ3FiNqMhzrHhs4xT46xE23FNphZoahLaMINXOQ2jkdPU/RkEmcAMdfYfFKZd
85BXVgMjjoNOVsu/HpecO0X4ONLs1pCVpz3U1gBtAjSB9s7DOo2brsGCYbVxM+O9
a8nf1ayWcDJ5iwF5CYgQiPEsSs/pidpiPAMYBMw10JxO//gXk/j0hMz2HL5y7KMA
DdLB3GoG7yRy1RNhhmS+chu9jvcKLhF1fIFHq2LVQGJ42DVhB9jk7jnZM82XjIFe
qU6HhDo6FRiHDS+nuGUz5wIDAQABo4GcMIGZMA4GA1UdDwEB/wQEAwIFoDATBgNV
HSUEDDAKBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBScI2gaHUMo
W8cVGvXie+CPi0dq4zAfBgNVHSMEGDAWgBQvPPO5g4dG+J5jFGvxgZnrvW8qhzAk
BgNVHREEHTAbgg5ob3N0MS50ZXN0LmNvbYIJbG9jYWxob3N0MA0GCSqGSIb3DQEB
CwUAA4IBAQBmhqgfw/USsEWrgSPlPj25D2vtY/I86zhxpXRtGaqrJBxE2TPdEAh9
bUDt5jJD7OhlRlnAigFD68x+6gSiYOAn8f0PAtq7BjxEyHpDvmMiySMU1RCohOY3
o/LdqB1L8m0FYiPoVOwKAWaK2Nl0mU66aXxf3rb99htXUEELv6vRYd4UFQmZonZx
P/rz4jPSrXEZ7svt9wrSEW4NAOpLwKbUmIM/RKQkhfc6Cl9pKqBenbKiJqN2Enug
XixZXw7/ZG/DfTXkiubCM8M6mHzWABg4f5LQTleHgOZ5WUTk9kzo2LoChTDmpSvb
p6m/Wo0EWR7qZvaH46vkWIPcAh+55teY
-----END CERTIFICATE-----
	`

	expired = `
-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIUchCG0LQyXuDHWO0BPYBHO3xgBo0wDQYJKoZIhvcNAQEL
BQAwbTELMAkGA1UEBhMCR0IxEDAOBgNVBAgTB0VuZ2xhbmQxDzANBgNVBAcTBkxv
bmRvbjENMAsGA1UEChMEVEVTVDEVMBMGA1UECxMMVEVTVCBSb290IENBMRUwEwYD
VQQDEwxURVNUIFJvb3QgQ0EwHhcNMTkxMjMxMjM1OTAwWhcNMTkxMjMxMjM1OTAw
WjBsMQswCQYDVQQGEwJHQjEQMA4GA1UECBMHRW5nbGFuZDEPMA0GA1UEBxMGTG9u
ZG9uMQ0wCwYDVQQKEwRUZXN0MRMwEQYDVQQLEwpUZXN0IEhvc3RzMRYwFAYDVQQD
Ew1ob3N0LnRlc3QuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
oDiZOcVxTxOFZIwIAAjHsyXqTz3Hht5iySMyDbApw6C6aHHWVBur1uUnhTh8ek7f
8DbLZ3FiNqMhzrHhs4xT46xE23FNphZoahLaMINXOQ2jkdPU/RkEmcAMdfYfFKZd
85BXVgMjjoNOVsu/HpecO0X4ONLs1pCVpz3U1gBtAjSB9s7DOo2brsGCYbVxM+O9
a8nf1ayWcDJ5iwF5CYgQiPEsSs/pidpiPAMYBMw10JxO//gXk/j0hMz2HL5y7KMA
DdLB3GoG7yRy1RNhhmS+chu9jvcKLhF1fIFHq2LVQGJ42DVhB9jk7jnZM82XjIFe
qU6HhDo6FRiHDS+nuGUz5wIDAQABo4GcMIGZMA4GA1UdDwEB/wQEAwIFoDATBgNV
HSUEDDAKBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBScI2gaHUMo
W8cVGvXie+CPi0dq4zAfBgNVHSMEGDAWgBQvPPO5g4dG+J5jFGvxgZnrvW8qhzAk
BgNVHREEHTAbgg5ob3N0MS50ZXN0LmNvbYIJbG9jYWxob3N0MA0GCSqGSIb3DQEB
CwUAA4IBAQAWI1Qm1STE8AFEVC76tMJ/a0SwLjfsn3qJwjap2O7HB8h5sPt9C3eM
rcpmGMuwUmE3FjUlUEP+QjLZTKuDgDzoOmlSASV+5cnfQe4w5rOXNYG4AFOMYxl4
+47OOYo8wYA7EeSkkJPXgtHybn/xMMMw+75vcNMYyQIKiB1lY9Y7id8wXM2VTeLC
YG5pjrQCU2QVNJGmanknsouqAZRVvTmOiEFj90rqrKtahNX6w00WsIcraXgE+c/S
A0d6vzryhM5HUiHKUSKea3kCdGcJeIvKIAJXnc5WCG8kbSXK3hAc9YfQ+iggJARi
sTEZmCbs9xPaMV2nwvv7zzLtTtVCDFiH
-----END CERTIFICATE-----
	`

	ca = `
-----BEGIN CERTIFICATE-----
MIIDzjCCAragAwIBAgIUHm6+iLd5YbWvhrGctYU+kJP3FvEwDQYJKoZIhvcNAQEL
BQAwbTELMAkGA1UEBhMCR0IxEDAOBgNVBAgTB0VuZ2xhbmQxDzANBgNVBAcTBkxv
bmRvbjENMAsGA1UEChMEVEVTVDEVMBMGA1UECxMMVEVTVCBSb290IENBMRUwEwYD
VQQDEwxURVNUIFJvb3QgQ0EwHhcNMjAwNTEzMTI0MjAwWhcNMjUwNTEyMTI0MjAw
WjBtMQswCQYDVQQGEwJHQjEQMA4GA1UECBMHRW5nbGFuZDEPMA0GA1UEBxMGTG9u
ZG9uMQ0wCwYDVQQKEwRURVNUMRUwEwYDVQQLEwxURVNUIFJvb3QgQ0ExFTATBgNV
BAMTDFRFU1QgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AM230Ldx9H+3HS1LAmnKoiiqddSrJFkYQx62M/HMxsye7fw8u4PpfLfXUetbaxtB
CGZTjCI49OrF2W4W5OTBaeorumcwcsYRMjs4/O92LvsOScKzneAGHbAEqpISXiZE
exZg2+jcWQdtXWxvafJ9wwvhB4jnd8SgioIlQB+oH+Z8eBDrnWXgUCqzceRMmW+/
ztjX85bfdvqhVIYUKt2+G5oyZ4LNMjZv95nZqIEbpoNpDIn75QWCiX8MthY/SKLm
8mh945zxYxeFiy2SWw+Na1p5pfzmnGAE95eNvjaGe/PrqKPN+YwdL7cmk9jwwnbV
/W+4WNUAGNK4xBpv2eODNH8CAwEAAaNmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1Ud
EwEB/wQIMAYBAf8CAQIwHQYDVR0OBBYEFC8887mDh0b4nmMUa/GBmeu9byqHMB8G
A1UdIwQYMBaAFC8887mDh0b4nmMUa/GBmeu9byqHMA0GCSqGSIb3DQEBCwUAA4IB
AQBbvQFGcOPJzri2Q1Z+d9aEiBKSd2nmKaS7okAmbKFLKa8IsQMD/Tj8HVNvFTUf
rG64Fzy4SKf9QoRxG34kX9uysY+3Eo/VkoMz2brO4041GjqFcvHjCcBOMESP/rjD
wpi/qy+PU5YO1MQ8u5/M7sFlu46/ExmhevMI6j6DZzbJoDoF08Tr3ZKoP4wt0FB1
jLdiNKZM6byw3dHlNDZWxC78ztzNVcei4tl1iaK86PEQw5sK/tmzn5fMoxDGUlrY
CfbpqGLiZ3CVvgBlKXhxGJnln//ummxEo+mGEoAV99Te0eN2TytAcgfJEGYxEqlR
r7uiIYhWM3RzrY4wBqukqnaY
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
	fmt.Println(info, err)

	// Output:
	// host.test.com <nil>
	// <nil> x509: certificate has expired or is not yet valid
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
