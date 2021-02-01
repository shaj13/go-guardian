package internal

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/shaj13/go-guardian/v2/auth"
)

// Requester sends an HTTP request to query
// an authorization server to determine the active state of an
// access token and to determine meta-information about this token.
type Requester struct {
	Addr     string
	Endpoint string
	Client   *http.Client
	// AdditionalData add more data to http request
	AdditionalData func(r *http.Request)
}

// Do sends the HTTP request and parse the HTTP response.
func (r *Requester) Do(ctx context.Context, data, review, status interface{}) error {
	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("Failed to marshal request body data, Type: %T, Err: %w", data, err)
	}

	url := r.Addr + r.Endpoint

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("Failed to create new HTTP request, Method: POST, URL: %s, Err: %w", url, err)
	}

	if r.AdditionalData != nil {
		r.AdditionalData(req)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.Client.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to send the HTTP request, Method: POST, URL: %s, Err: %w", url, err)
	}

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Failed to read the HTTP response, Method: POST, URL: %s, Err: %w", url, err)
	}

	defer resp.Body.Close()

	if err := json.Unmarshal(body, status); err == nil {
		return nil
	}

	if err := json.Unmarshal(body, review); err != nil {
		return fmt.Errorf("Failed to unmarshal response body data, Type: %T Err: %w", review, err)
	}

	return nil
}

// SetRequesterBearerToken sets ruqester token.
func SetRequesterBearerToken(token string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if r, ok := v.(*Requester); ok {
			r.AdditionalData = func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+token)
			}
		}
	})
}

// SetRequesterHTTPClient sets underlying requester http client.
func SetRequesterHTTPClient(c *http.Client) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if r, ok := v.(*Requester); ok {
			r.Client = c
		}
	})
}

// SetRequesterTLSConfig sets underlying requester http client tls config.
func SetRequesterTLSConfig(tls *tls.Config) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if r, ok := v.(*Requester); ok {
			r.Client.Transport.(*http.Transport).TLSClientConfig = tls
		}
	})
}

// SetRequesterClientTransport sets underlying requester http client transport.
func SetRequesterClientTransport(rt http.RoundTripper) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if r, ok := v.(*Requester); ok {
			r.Client.Transport = rt
		}
	})
}

// SetRequesterAddress sets requester origin server address
// e.g http://host:port or https://host:port.
func SetRequesterAddress(addr string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if r, ok := v.(*Requester); ok {
			r.Addr = strings.TrimSuffix(addr, "/")
		}
	})
}

// SetRequesterEndpoint sets requester origin server endpoint.
// e.g /api/v1/token
func SetRequesterEndpoint(endpoint string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if r, ok := v.(*Requester); ok {
			r.Addr = "/" + strings.TrimSuffix(endpoint, "/")
		}
	})
}
