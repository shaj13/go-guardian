package errors 

import "reflect"

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
