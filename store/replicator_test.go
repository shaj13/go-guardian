package store

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestReplicatorLoad(t *testing.T) {
	const (
		key      = "key"
		value    = "value"
		funcName = "Load"
	)

	table := []struct {
		name        string
		value       interface{}
		found       bool
		expectedErr bool
		prepare     func() (Cache, Cache)
	}{
		{
			name:        "it return false when key does not exist in both caches",
			value:       nil,
			found:       false,
			expectedErr: false,
			prepare: func() (Cache, Cache) {
				p := &mockCache{
					Mock: mock.Mock{},
				}

				m := &mockCache{
					Mock: mock.Mock{},
				}

				p.On(funcName).Return(nil, false, nil)
				m.On(funcName).Return(nil, false, nil)

				return p, m
			},
		},
		{
			name:        "it return value from Persistent cache when in memory return error",
			value:       value,
			found:       true,
			expectedErr: false,
			prepare: func() (Cache, Cache) {
				p := &mockCache{
					Mock: mock.Mock{},
				}

				m := &mockCache{
					Mock: mock.Mock{},
				}

				p.On(funcName).Return(value, true, nil)
				m.On(funcName).Return(nil, false, fmt.Errorf("Replicator test #L56"))
				m.On("Store").Return(nil)
				return p, m
			},
		},
		{
			name:        "it return error from Persistent cache",
			value:       nil,
			found:       false,
			expectedErr: true,
			prepare: func() (Cache, Cache) {
				p := &mockCache{
					Mock: mock.Mock{},
				}

				m := &mockCache{
					Mock: mock.Mock{},
				}

				p.On(funcName).Return(nil, false, fmt.Errorf("Replicator test #78"))
				m.On(funcName).Return(nil, false, nil)
				return p, m
			},
		},
		{
			name:        "it return value from memory cache",
			value:       value,
			found:       true,
			expectedErr: false,
			prepare: func() (Cache, Cache) {
				p := &mockCache{
					Mock: mock.Mock{},
				}

				m := &mockCache{
					Mock: mock.Mock{},
				}

				m.On(funcName).Return(value, true, nil)
				return p, m
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			p, m := tt.prepare()

			r := &Replicator{
				Persistent: p,
				InMemory:   m,
			}

			v, ok, err := r.Load(key, nil)

			assert.Equal(t, tt.value, v)
			assert.Equal(t, tt.found, ok)
			assert.Equal(t, tt.expectedErr, err != nil)
		})
	}
}

func TestReplicatorStore(t *testing.T) {
	const funcName = "Store"

	table := []struct {
		name        string
		expectedErr bool
		prepare     func() (Cache, Cache)
	}{
		{
			name:        "it return error when Persistent cache return error ",
			expectedErr: true,
			prepare: func() (Cache, Cache) {
				p := &mockCache{
					Mock: mock.Mock{},
				}

				m := &mockCache{
					Mock: mock.Mock{},
				}

				p.On(funcName).Return(fmt.Errorf("Replicator test #L140"))
				return p, m
			},
		},
		{
			name:        "it return nil error when memory cache return error ",
			expectedErr: false,
			prepare: func() (Cache, Cache) {
				p := &mockCache{
					Mock: mock.Mock{},
				}

				m := &mockCache{
					Mock: mock.Mock{},
				}

				p.On(funcName).Return(nil)
				m.On(funcName).Return(fmt.Errorf("Replicator test #L140"))
				return p, m
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			p, m := tt.prepare()

			r := &Replicator{
				Persistent: p,
				InMemory:   m,
			}

			err := r.Store("key", "value", nil)
			assert.Equal(t, tt.expectedErr, err != nil)
		})
	}
}

func TestReplicatorDelete(t *testing.T) {
	const funcName = "Delete"

	table := []struct {
		name        string
		expectedErr bool
		prepare     func() (Cache, Cache)
	}{
		{
			name:        "it return error when Persistent cache return error ",
			expectedErr: true,
			prepare: func() (Cache, Cache) {
				p := &mockCache{
					Mock: mock.Mock{},
				}

				m := &mockCache{
					Mock: mock.Mock{},
				}

				p.On(funcName).Return(fmt.Errorf("Replicator test #L201"))
				return p, m
			},
		},
		{
			name:        "it return nil error when memory cache return error ",
			expectedErr: false,
			prepare: func() (Cache, Cache) {
				p := &mockCache{
					Mock: mock.Mock{},
				}

				m := &mockCache{
					Mock: mock.Mock{},
				}

				p.On(funcName).Return(nil)
				m.On(funcName).Return(fmt.Errorf("Replicator test #L140"))
				return p, m
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			p, m := tt.prepare()

			r := &Replicator{
				Persistent: p,
				InMemory:   m,
			}

			err := r.Delete("key", nil)
			assert.Equal(t, tt.expectedErr, err != nil)
		})
	}
}

func TestReplicatorKeys(t *testing.T) {
	p := &mockCache{
		Mock: mock.Mock{},
	}

	r := &Replicator{
		Persistent: p,
	}

	keys := []string{"1", "2", "3"}
	p.On("Keys").Return(keys)
	got := r.Keys()

	assert.Equal(t, keys, got)
}

func TestReplicatorIsSynced(t *testing.T) {
	const funcName = "Keys"

	table := []struct {
		name     string
		expected bool
		prepare  func() (Cache, Cache)
	}{
		{
			name:     "it return true when Persistent and memory synced",
			expected: true,
			prepare: func() (Cache, Cache) {
				p := &mockCache{
					Mock: mock.Mock{},
				}

				m := &mockCache{
					Mock: mock.Mock{},
				}

				keys := []string{"1"}

				p.On(funcName).Return(keys)
				m.On(funcName).Return(keys)
				return p, m
			},
		},
		{
			name:     "it return false when Persistent and memory keys are not equal",
			expected: false,
			prepare: func() (Cache, Cache) {
				p := &mockCache{
					Mock: mock.Mock{},
				}

				m := &mockCache{
					Mock: mock.Mock{},
				}

				p.On(funcName).Return([]string{"1", "2"})
				m.On(funcName).Return([]string{"1"})
				return p, m
			},
		},
		{
			name:     "it return false when Persistent and memory keys are not deep equal",
			expected: false,
			prepare: func() (Cache, Cache) {
				p := &mockCache{
					Mock: mock.Mock{},
				}

				m := &mockCache{
					Mock: mock.Mock{},
				}

				p.On(funcName).Return([]string{"1", "2"})
				m.On(funcName).Return([]string{"1", "3"})
				return p, m
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			p, m := tt.prepare()

			r := &Replicator{
				Persistent: p,
				InMemory:   m,
			}

			got := r.IsSynced()
			assert.Equal(t, tt.expected, got)
		})
	}
}

type mockCache struct {
	mock.Mock
}

func (m *mockCache) Load(key string, req *http.Request) (interface{}, bool, error) {
	args := m.Called()
	return args.Get(0), args.Bool(1), args.Error(2)
}

func (m *mockCache) Store(key string, value interface{}, _ *http.Request) error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockCache) Delete(key string, _ *http.Request) error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockCache) Keys() []string {
	args := m.Called()
	return args.Get(0).([]string)
}
