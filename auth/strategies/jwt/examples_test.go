package jwt_test

import (
	"fmt"
	"net/http"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/jwt"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"

	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/lru"
)

type RotatedSecrets struct {
	Secrtes          map[string][]byte
	LatestID         string
	RotationDuration time.Duration
	LastRotation     time.Time
}

func (r RotatedSecrets) KID() string {
	if time.Now().After(r.LastRotation) {
		r.LastRotation = time.Now().Add(r.RotationDuration)
		r.LatestID = "your generated id"
		r.Secrtes[r.LatestID] = []byte("your generated secrets")
	}
	return r.LatestID
}

func (r RotatedSecrets) Get(kid string) (key interface{}, alg string, err error) {
	s, ok := r.Secrtes[kid]
	if ok {
		return s, jwt.HS256, nil
	}
	return nil, "", fmt.Errorf("Invalid KID %s", kid)
}

func Example() {
	u := auth.NewUserInfo("example", "example", nil, nil)
	c := libcache.LRU.New(0)
	s := jwt.StaticSecret{
		ID:        "id",
		Algorithm: jwt.HS256,
		Secret:    []byte("your secret"),
	}

	token, err := jwt.IssueAccessToken(u, s)
	strategy := jwt.New(c, s)

	fmt.Println(err)

	// user request
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	user, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(user.GetID(), err)

	// Output:
	// <nil>
	// example <nil>
}

func Example_scope() {
	opt := token.SetScopes(token.NewScope("read:example", "/example", "GET"))
	ns := jwt.SetNamedScopes("read:example")
	u := auth.NewUserInfo("example", "example", nil, nil)
	c := libcache.LRU.New(0)
	s := jwt.StaticSecret{
		ID:        "id",
		Algorithm: jwt.HS256,
		Secret:    []byte("your secret"),
	}

	token, err := jwt.IssueAccessToken(u, s, ns)
	strategy := jwt.New(c, s, opt)

	fmt.Println(err)

	// user request
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	_, err = strategy.Authenticate(r.Context(), r)
	fmt.Println(err)

	// Output:
	// <nil>
	// strategies/token: The access token scopes do not grant access to the requested resource
}

func ExampleSecretsKeeper() {
	// The example shows how to create your custom secrets keeper to rotate secrets.
	s := RotatedSecrets{
		Secrtes: make(map[string][]byte),
	}
	u := auth.NewUserInfo("example", "example", nil, nil)
	c := libcache.LRU.New(0)

	token, err := jwt.IssueAccessToken(u, s)
	strategy := jwt.New(c, s)

	fmt.Println(err)

	// user request
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	user, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(user.GetID(), err)

	// Output:
	// <nil>
	// example <nil>
}

func ExampleSetAudience() {
	aud := jwt.SetAudience("example-aud")
	u := auth.NewUserInfo("example", "example", nil, nil)
	s := jwt.StaticSecret{}
	c := libcache.LRU.New(0)

	_, _ = jwt.IssueAccessToken(u, s, aud)
	_ = jwt.New(c, s, aud)
}

func ExampleSetIssuer() {
	iss := jwt.SetIssuer("example-iss")
	u := auth.NewUserInfo("example", "example", nil, nil)
	s := jwt.StaticSecret{}
	c := libcache.LRU.New(0)

	_, _ = jwt.IssueAccessToken(u, s, iss)
	_ = jwt.New(c, s, iss)
}

func ExampleSetExpDuration() {
	exp := jwt.SetExpDuration(time.Hour)
	u := auth.NewUserInfo("example", "example", nil, nil)
	s := jwt.StaticSecret{}
	c := libcache.LRU.New(0)

	_, _ = jwt.IssueAccessToken(u, s, exp)
	_ = jwt.New(c, s, exp)
}

func ExampleSetNamedScopes() {
	u := auth.NewUserInfo("example", "example", nil, nil)
	ns := jwt.SetNamedScopes("read:example")
	// get jwt scope verification option
	opt := token.SetScopes(token.NewScope("read:example", "/example", "GET"))
	s := jwt.StaticSecret{}
	c := libcache.LRU.New(0)

	_, _ = jwt.IssueAccessToken(u, s, ns)
	_ = jwt.New(c, s, opt)
}
