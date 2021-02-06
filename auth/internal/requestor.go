package internal

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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
	Method   string
	// Keep Unmarshalling body for all given types, by default stop after the first match
	KeepUnmarshalling bool
	Client            *http.Client
	// AdditionalData add more data to http request
	AdditionalData func(r *http.Request)
	Unmarshal      func(data []byte, v interface{}) error
	Marshal        func(v interface{}) ([]byte, error)
}

// Do sends the HTTP request and parse the HTTP response.
func (r *Requester) Do(ctx context.Context, data, review, status interface{}) (*http.Response, error) {
	f := func(*http.Request) {}
	return r.do(ctx, f, data, review, status)
}

// DoWithf same as Do but it accepts f to add additional  information to the request.
func (r *Requester) DoWithf(ctx context.Context, f func(*http.Request), data, review, status interface{}) (*http.Response, error) { //nolint:lll
	return r.do(ctx, f, data, review, status)
}

func (r *Requester) do(ctx context.Context, f func(r *http.Request), data, review, status interface{}) (*http.Response, error) { //nolint:lll
	url := r.Addr + r.Endpoint

	reader, err := r.reader(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("Failed to create new HTTP request, Method: %s, URL: %s, Err: %w", r.Method, url, err)
	}

	f(req)

	if r.AdditionalData != nil {
		r.AdditionalData(req)
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to send the HTTP request, Method: POST, URL: %s, Err: %w", url, err)
	}

	if resp.Body == http.NoBody {
		return resp, nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read the HTTP response, Method: POST, URL: %s, Err: %w", url, err)
	}

	defer resp.Body.Close()

	if err := r.Unmarshal(body, status); err == nil && !r.KeepUnmarshalling {
		return resp, nil
	}

	if err := r.Unmarshal(body, review); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal response body data, Type: %T Err: %w", review, err)
	}

	return resp, nil
}

func (r *Requester) reader(data interface{}) (io.Reader, error) {
	if data == nil {
		return http.NoBody, nil
	}

	body, err := r.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal request body data, Type: %T, Err: %w", data, err)
	}

	return bytes.NewBuffer(body), nil
}

// SetHeader for all outgoing request's.
func (r *Requester) SetHeader(key, value string) {
	additionalData := r.AdditionalData
	r.AdditionalData = func(r *http.Request) {
		r.Header.Set(key, value)
		if additionalData != nil {
			additionalData(r)
		}
	}
}

// NewRequester returns new requester instance.
func NewRequester(addr string) *Requester {
	r := new(Requester)
	r.Method = http.MethodPost
	r.Addr = addr
	r.Endpoint = ""
	r.Marshal = json.Marshal
	r.Unmarshal = json.Unmarshal
	r.Client = &http.Client{
		Transport: &http.Transport{},
	}
	return r
}

// ----------------------------------------------------------------------------
// Auth Options
// ----------------------------------------------------------------------------

// SetRequesterMethod sets ruqester http method.
func SetRequesterMethod(method string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if r, ok := v.(*Requester); ok {
			r.Method = method
		}
	})
}

// SetRequesterBearerToken sets ruqester token.
func SetRequesterBearerToken(token string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if r, ok := v.(*Requester); ok {
			r.SetHeader("Authorization", "Bearer "+token)
		}
	})
}

// SetRequesterBasicAuth sets ruqester basic auth.
func SetRequesterBasicAuth(username, password string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if r, ok := v.(*Requester); ok {
			additionalData := r.AdditionalData
			r.AdditionalData = func(r *http.Request) {
				r.SetBasicAuth(username, password)
				if additionalData != nil {
					additionalData(r)
				}
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
