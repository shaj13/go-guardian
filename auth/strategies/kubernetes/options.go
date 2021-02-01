package kubernetes

import (
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/internal"
)

// SetServiceAccountToken sets kubernetes service account token
// for token review API.
func SetServiceAccountToken(token string) auth.Option {
	return internal.SetRequesterBearerToken(token)
}

// SetHTTPClient sets underlying http client.
func SetHTTPClient(c *http.Client) auth.Option {
	return internal.SetRequesterHTTPClient(c)
}

// SetTLSConfig sets tls config for kubernetes api.
func SetTLSConfig(tls *tls.Config) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if k, ok := v.(*kubeReview); ok {
			k.requester.Client.Transport.(*http.Transport).TLSClientConfig = tls
		}
	})
}

// SetClientTransport sets underlying http client transport.
func SetClientTransport(rt http.RoundTripper) auth.Option {
	return internal.SetRequesterClientTransport(rt)
}

// SetAddress sets kuberntess api server address
// e.g http://host:port or https://host:port.
func SetAddress(addr string) auth.Option {
	return internal.SetRequesterAddress(addr)
}

// SetAPIVersion sets kuberntess api version.
// e.g authentication.k8s.io/v1
func SetAPIVersion(version string) auth.Option {
	version = strings.TrimPrefix(strings.TrimSuffix(version, "/"), "/")
	return internal.SetRequesterAddress("/apis/" + version + "/tokenreviews")
}

// SetAudiences sets the list of the identifiers that the resource server presented
// with the token identifies as.
func SetAudiences(auds []string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if k, ok := v.(*kubeReview); ok {
			k.audiences = auds
		}
	})
}
