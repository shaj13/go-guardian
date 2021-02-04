package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtensionsClone(t *testing.T) {
	// Round #1 cloned and original equal values
	ext := make(Extensions)
	ext.Add("key-1", "value 1")
	ext.Add("key-2", "value 2")
	cloned := ext.Clone()

	assert.EqualValues(t, ext, cloned)

	// Round #2 change cloned should not affect original
	cloned.Add("key-3", "value 3")
	assert.NotEqualValues(t, ext, cloned)

	// Round #2 change original should not affect cloned
	ext.Add("key-4", "value 4")
	assert.NotEqualValues(t, ext, cloned)
}
