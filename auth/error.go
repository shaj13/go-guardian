package auth

import "fmt"

// Error represents an object that contains multiple errors.
type Error interface {
	error
	Errors() []error
}

type authError []error

func (errs authError) Error() string {
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

func (errs authError) Errors() []error {
	return errs
}
