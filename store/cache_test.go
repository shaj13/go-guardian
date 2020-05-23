package store

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// nolint:goconst
func TestFIFO(t *testing.T) {
	table := []struct {
		name        string
		key         string
		value       interface{}
		op          string
		expectedErr bool
		found       bool
	}{
		{
			name:        "it return err when key expired",
			op:          "load",
			key:         "expired",
			expectedErr: true,
			found:       true,
		},
		{
			name:  "it return false when key does not exist",
			op:    "load",
			key:   "key",
			found: false,
		},
		{
			name:  "it return true and value when exist",
			op:    "load",
			key:   "test",
			value: "test",
			found: true,
		},
		{
			name:  "it overwrite exist key and value when store",
			op:    "store",
			key:   "test",
			value: "test2",
			found: true,
		},
		{
			name:  "it create new record when store",
			op:    "store",
			key:   "key",
			value: "value",
			found: true,
		},
		{
			name:  "it's not crash when trying to delete a non exist record",
			key:   "key",
			found: false,
		},
		{
			name:  "it delete a exist record",
			op:    "delete",
			key:   "test",
			found: false,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {

			queue := &queue{
				notify: make(chan struct{}, 10),
				mu:     &sync.Mutex{},
			}

			cache := &fifo{
				queue: queue,
				ttl:   time.Second,
				records: map[string]*record{
					"test": {
						value: "test",
						exp:   time.Now().Add(time.Hour),
					},
					"expired": {
						value: "expired",
						exp:   time.Now().Add(-time.Hour),
					},
				},
				mu: &sync.Mutex{},
			}

			r, _ := http.NewRequest("GET", "/", nil)
			var err error

			switch tt.op {
			case "load":
				v, ok, err := cache.Load(tt.key, r)
				assert.Equal(t, tt.value, v)
				assert.Equal(t, tt.found, ok)
				assert.Equal(t, tt.expectedErr, err != nil)
				return
			case "store":
				err = cache.Store(tt.key, tt.value, r)
				assert.Equal(t, tt.key, queue.next().key)
			case "delete":
				err = cache.Delete(tt.key, r)
			}

			assert.Equal(t, tt.expectedErr, err != nil)
			v, ok := cache.records[tt.key]
			assert.Equal(t, tt.found, ok)

			if tt.value != nil {
				assert.Equal(t, tt.value, v.value)
			}
		})
	}
}

func TestQueue(t *testing.T) {
	queue := &queue{
		notify: make(chan struct{}, 10),
		mu:     &sync.Mutex{},
	}

	for i := 0; i < 5; i++ {
		queue.push(
			&record{
				key:   "any",
				value: i,
			})
	}

	for i := 0; i < 5; i++ {
		r := queue.next()
		assert.Equal(t, i, r.value)
	}
}

func TestQueueNotify(t *testing.T) {
	done := make(chan struct{})

	queue := &queue{
		notify: make(chan struct{}),
		mu:     &sync.Mutex{},
	}

	go func() {
		counter := 0
		for {
			<-queue.notify
			counter++
			if counter == 5 {
				done <- struct{}{}
				return
			}

		}
	}()

	for i := 0; i < 5; i++ {
		queue.push(nil)
		queue.next()
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Something wrong expected test to send done")
	}
}

func TestGC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cache := NewFIFO(ctx, time.Nanosecond*50)

	cache.Store("1", 1, nil)
	cache.Store("2", 2, nil)

	time.Sleep(time.Millisecond)
	_, ok, _ := cache.Load("1", nil)
	assert.False(t, ok)

	_, ok, _ = cache.Load("2", nil)
	assert.False(t, ok)
}
