package ldap

import (
	"fmt"
	"net/http"
)

func Example() {
	cfg := Config{
		BaseDN:       "dc=example,dc=org",
		BindDN:       "cn=readonly,dc=example,dc=org",
		URL:          "ldap://127.0.0.1:389",
		BindPassword: "readonly",
		Filter:       "(cn=%s)",
	}

	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth("admin", "admin")

	info, err := New(&cfg).Authenticate(r.Context(), r)
	fmt.Println(info, err != nil)
	// Output:
	// <nil> true
}
