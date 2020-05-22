package errors

import (
	"fmt"
	"reflect"
)

// InvalidType represent invalid type assertion error.
type InvalidType struct {
	Want string
	Got  string
}

// Error describe error as a string
func (i InvalidType) Error() string {
	return "Invalid type assertion: Want " + i.Want + " Got " + i.Got
}

// NewInvalidType returns InvalidType error
func NewInvalidType(want, got interface{}) error {
	f := func(v interface{}) string {
		if v == nil {
			return "<nil>"
		}
		return reflect.TypeOf(v).String()
	}

	return InvalidType{
		Want: f(want),
		Got:  f(got),
	}
}

// MultiError stores multiple errors.
type MultiError []error

func (errs MultiError) Error() string {
	if len(errs) == 0 {
		return ""
	}

	if len(errs) == 1 {
		return errs[0].Error()
	}

	str := ""

	for _, err := range errs[1:] {
		str += err.Error() + ", "
	}

	return fmt.Sprintf("%v: [%s]", errs[0], str)
}
