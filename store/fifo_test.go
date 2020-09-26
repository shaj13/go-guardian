package store

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFIFOStore(t *testing.T) {
	const key = "key"

	queue := &queue{
		notify: make(chan struct{}, 1),
		mu:     new(sync.Mutex),
	}

	cache := &FIFO{
		MU:      new(sync.Mutex),
		records: make(map[string]*record, 1),
		queue:   queue,
	}

	err := cache.Store(key, "value", nil)
	_, ok := cache.records[key]
	r := queue.next()

	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, key, r.Key)
}

func TestFIFOUpdate(t *testing.T) {
	const (
		key   = "key"
		value = "value"
	)

	cache := &FIFO{
		MU:      new(sync.Mutex),
		records: make(map[string]*record, 1),
	}
	cache.records[key] = new(record)

	err := cache.Update(key, value, nil)
	r := cache.records[key]

	assert.NoError(t, err)
	assert.Equal(t, value, r.Value)
}

func TestFIFODelete(t *testing.T) {
	table := []struct {
		name  string
		key   string
		value interface{}
	}{
		{
			name: "it's not crash when trying to delete a non exist record",
			key:  "key",
		},
		{
			name:  "it delete a exist record",
			key:   "key",
			value: "value",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			cache := &FIFO{
				MU:      new(sync.Mutex),
				records: make(map[string]*record, 1),
			}

			if tt.value != nil {
				cache.records[tt.key] = new(record)
			}

			err := cache.Delete(tt.key, nil)
			_, ok := cache.records[tt.key]

			assert.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

func TestFifoLoad(t *testing.T) {
	table := []struct {
		name  string
		key   string
		value interface{}
		add   bool
		found bool
		exp   time.Time
		err   error
	}{
		{
			name:  "it return err when key expired",
			key:   "expired",
			add:   true,
			found: true,
			exp:   time.Now().Add(-time.Hour),
			err:   ErrCachedExp,
		},
		{
			name: "it return false when key does not exist",
			key:  "key",
		},
		{
			name:  "it return true and value when exist",
			exp:   time.Now().Add(time.Hour),
			found: true,
			add:   true,
			key:   "test",
			value: "test",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			cache := &FIFO{
				MU:      new(sync.Mutex),
				records: make(map[string]*record, 1),
			}

			if tt.add {
				r := &record{
					Exp:   tt.exp,
					Key:   tt.key,
					Value: tt.value,
				}

				cache.records[tt.key] = r
			}

			v, ok, err := cache.Load(tt.key, nil)

			assert.Equal(t, tt.value, v)
			assert.Equal(t, tt.err, err)
			assert.Equal(t, tt.found, ok)
		})
	}
}

func TestFIFOEvict(t *testing.T) {
	evictedKeys := make([]string, 0)
	onEvictedFun := func(key string, value interface{}) {
		evictedKeys = append(evictedKeys, key)
	}

	fifo := NewFIFO(context.Background(), 1)
	fifo.OnEvicted = onEvictedFun

	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("myKey%d", i)
		fifo.Store(key, 1234, nil)
	}

	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("myKey%d", i)
		fifo.Delete(key, nil)
	}

	assert.Equal(t, 10, len(evictedKeys))

	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("myKey%d", i)
		assert.Equal(t, key, evictedKeys[i])
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
				Key:   "any",
				Value: i,
			})
	}

	for i := 0; i < 5; i++ {
		r := queue.next()
		assert.Equal(t, i, r.Value)
	}
}

func TestFifoKeys(t *testing.T) {
	ctx, cacnel := context.WithCancel(context.Background())
	defer cacnel()

	f := NewFIFO(ctx, time.Minute)

	f.Store("1", "", nil)
	f.Store("2", "", nil)
	f.Store("3", "", nil)

	assert.ElementsMatch(t, []string{"1", "2", "3"}, f.Keys())
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

func BenchmarkFIFIO(b *testing.B) {
	cache := NewFIFO(context.Background(), time.Minute)
	benchmarkCache(b, cache)
}

func benchmarkCache(b *testing.B, cache Cache) {
	keys := []string{}

	for i := 0; i < 100; i++ {
		key := strconv.Itoa(i)
		keys = append(keys, key)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			key := keys[rand.Intn(100)]
			_, ok, _ := cache.Load(key, nil)
			if ok {
				cache.Delete(key, nil)
			} else {
				cache.Store(key, struct{}{}, nil)
			}
		}
	})
}
