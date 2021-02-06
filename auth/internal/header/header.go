package header

import (
	"net/http"
	"strings"

	"github.com/golang/gddo/httputil/header"
)

// ParsePairs extracts key/value pairs from a comma-separated list of values as
// described by RFC 2068 and returns a map[key]value.
// The resulting values are unquoted.
// If a list element doesn't contain a "=", the key is the element itself and the value is an empty string.
func ParsePairs(h http.Header, key string) map[string]string {
	m := make(map[string]string)
	for _, pair := range header.ParseList(h, key) {
		if i := strings.Index(pair, "="); i < 0 {
			m[pair] = ""
		} else {
			v := pair[i+1:]
			if v[0] == '"' && v[len(v)-1] == '"' {
				// Unquote it.
				v = v[1 : len(v)-1]
			}
			m[pair[:i]] = v
		}
	}
	return m
}
