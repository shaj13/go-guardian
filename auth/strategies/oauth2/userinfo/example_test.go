package userinfo_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/lru"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2/userinfo"
)

type ExampleClaims struct {
	ExtensionField string `json:"extension_field"`
	*userinfo.Claims
}

func (c ExampleClaims) New() oauth2.ClaimsResolver {
	claim := userinfo.Claims{}.New().(*userinfo.Claims)
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
	return nil
}

func Example() {
	srv := AuthrizationServer()
	opt := userinfo.SetHTTPClient(srv.Client())
	strategy := userinfo.New(srv.URL, libcache.LRU.New(0), opt)
	r, _ := http.NewRequest("GET", "/protected/resource", nil)
	r.Header.Set("Authorization", "Bearer <oauth2-token>")
	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(info.GetUserName(), err)
	// Output:
	// jdoe <nil>
}

func ExampleSetClaimResolver() {
	srv := AuthrizationServer()
	opt := userinfo.SetClaimResolver(new(ExampleClaims))
	strategy := userinfo.New(srv.URL, libcache.LRU.New(0), opt)
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
			"preferred_username": "jdoe",
			"sub": "Z5O3upPC88QrAjx00dis",
			"extension_field": "twenty-seven"
		}
		`
		w.WriteHeader(200)
		w.Write([]byte(body))
	}
	return httptest.NewServer(http.HandlerFunc(h))
}
