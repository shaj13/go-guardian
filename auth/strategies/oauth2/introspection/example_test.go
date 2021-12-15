package introspection_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/lru"

	"github.com/m87carlson/go-guardian/v2/auth"
	"github.com/m87carlson/go-guardian/v2/auth/claims"
	"github.com/m87carlson/go-guardian/v2/auth/strategies/oauth2"
	"github.com/m87carlson/go-guardian/v2/auth/strategies/oauth2/introspection"
	"github.com/m87carlson/go-guardian/v2/auth/strategies/token"
)

type ExampleClaims struct {
	ExtensionField string `json:"extension_field"`
	*introspection.Claims
}

func (c ExampleClaims) New() oauth2.ClaimsResolver {
	claim := introspection.Claims{}.New().(*introspection.Claims)
	return &ExampleClaims{Claims: claim}
}

func (c ExampleClaims) Resolve() auth.Info {
	return c
}

func (c ExampleClaims) Verify(opts claims.VerifyOptions) error {
	if v, ok := opts.Extra["extension_field"]; ok {
		str, ok := v.(string)
		if !ok {
			panic("Expected VerifyOptions.extension_field of type string")
		}
		if str != c.ExtensionField {
			return errors.New("ExampleClaim: Invalid ExtensionField")
		}
	}
	return c.Standard.Verify(opts)
}

func Example() {
	srv := AuthrizationServer()
	opt := introspection.SetHTTPClient(srv.Client())
	strategy := introspection.New(srv.URL, libcache.LRU.New(0), opt)
	r, _ := http.NewRequest("GET", "/protected/resource", nil)
	r.Header.Set("Authorization", "Bearer <oauth2-token>")
	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(info.GetUserName(), err)
	// Output:
	// jdoe <nil>
}

func Example_scope() {
	opt := token.SetScopes(token.NewScope("dolphin", "/dolphin", "GET|POST|PUT"))
	srv := AuthrizationServer()
	strategy := introspection.New(srv.URL, libcache.LRU.New(0), opt)
	r, _ := http.NewRequest("DELETE", "/dolphin", nil)
	r.Header.Set("Authorization", "Bearer <oauth2-token>")
	_, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(err)

	// Output:
	// strategies/token: The access token scopes do not grant access to the requested resource
}

func ExampleSetVerifyOptions() {
	srv := AuthrizationServer()
	client := introspection.SetHTTPClient(srv.Client())
	vopts := introspection.SetVerifyOptions(
		claims.VerifyOptions{
			Issuer: "https://server.example.org",
		})
	strategy := introspection.New(srv.URL, libcache.LRU.New(0), client, vopts)
	r, _ := http.NewRequest("GEt", "/protected/resource", nil)
	r.Header.Set("Authorization", "Bearer <oauth2-token>")
	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(info, err)
	// Output:
	// <nil> strategies/oauth2/introspection: claims: standard claims issuer name does not match the expected issuer
}

func ExampleSetClaimResolver() {
	srv := AuthrizationServer()
	opt := introspection.SetClaimResolver(new(ExampleClaims))
	strategy := introspection.New(srv.URL, libcache.LRU.New(0), opt)
	r, _ := http.NewRequest("GEt", "/protected/resource", nil)
	r.Header.Set("Authorization", "Bearer <oauth2-token>")
	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(info.(ExampleClaims).ExtensionField, err)
	// Output:
	// twenty-seven <nil>
}

func AuthrizationServer() *httptest.Server {
	h := func(w http.ResponseWriter, r *http.Request) {
		const body = `
		{
			"active": true,
			"client_id": "l238j323ds-23ij4",
			"username": "jdoe",
			"scope": "read write dolphin",
			"sub": "Z5O3upPC88QrAjx00dis",
			"aud": "https://protected.example.net/resource",
			"iss": "https://server.example.com/",
			"iat": 1419350238,
			"extension_field": "twenty-seven"
		}
		`
		w.WriteHeader(200)
		w.Write([]byte(body))
	}
	return httptest.NewServer(http.HandlerFunc(h))
}
