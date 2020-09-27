package auth

import (
	"reflect"
)

// TypeError represent invalid type assertion error.
type TypeError struct {
	prefix string
	Want   string
	Got    string
}

// Error describe error as a string
func (i TypeError) Error() string {
	return i.prefix + " Invalid type assertion: Want " + i.Want + " Got " + i.Got
}

// NewTypeError returns InvalidType error
func NewTypeError(prefix string, want, got interface{}) error {
	f := func(v interface{}) string {
		if v == nil {
			return "<nil>"
		}
		return reflect.TypeOf(v).String()
	}

	return TypeError{
		Want:   f(want),
		Got:    f(got),
		prefix: prefix,
	}
}
