package storage

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
	return InvalidType{
		Want: reflect.TypeOf(want).String(),
		Got:  reflect.TypeOf(got).String(),
	}
}
