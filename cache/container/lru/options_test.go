package lru

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCapacity(t *testing.T) {
	opt := Capacity(100)
	lru := New(opt).(*lru)

	assert.Equal(t, lru.c.Capacity, 100)
}

func TestRegisterOnEvicted(t *testing.T) {
	opt := RegisterOnEvicted(func(key, value interface{}) {})
	lru := New(opt).(*lru)

	assert.NotNil(t, lru.c.OnEvicted)
}

func TestRegisterOnExpired(t *testing.T) {
	opt := RegisterOnExpired(func(key interface{}) {})
	lru := New(opt).(*lru)

	assert.NotNil(t, lru.c.OnExpired)
}

func TestTTL(t *testing.T) {
	opt := TTL(time.Hour)
	lru := New(opt).(*lru)

	assert.Equal(t, lru.c.TTL, time.Hour)
}
