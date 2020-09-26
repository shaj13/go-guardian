package store

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// NewFIFO return a simple FIFO Cache instance safe for concurrent usage,
// And spawning a garbage collector goroutine to collect expired record.
// The cache send record to garbage collector through a queue when it stored a new one.
// Once the garbage collector received the record it checks if record not expired to wait until expiration,
// Otherwise, wait for the next record.
// When the all expired record collected the garbage collector will be blocked,
// until new record stored to repeat the process.
// The context will be Passed to garbage collector
func NewFIFO(ctx context.Context, ttl time.Duration) *FIFO {
	queue := &queue{
		notify: make(chan struct{}, 1),
		mu:     &sync.Mutex{},
	}

	f := &FIFO{
		queue:   queue,
		TTL:     ttl,
		records: make(map[string]*record),
		MU:      &sync.Mutex{},
	}

	go gc(ctx, queue, f)

	return f
}

// FIFO Cache instance safe for concurrent usage.
type FIFO struct {
	// TTL To expire a value in cache.
	// TTL Must be greater than 0.
	TTL time.Duration

	// OnEvicted optionally specifies a callback function to be
	// executed when an entry is purged from the cache.
	OnEvicted OnEvicted

	MU      *sync.Mutex
	records map[string]*record
	queue   *queue
}

// Load returns the value stored in the Cache for a key, or nil if no value is present.
// The ok result indicates whether value was found in the Cache.
func (f *FIFO) Load(key string, _ *http.Request) (interface{}, bool, error) {
	f.MU.Lock()
	defer f.MU.Unlock()

	record, ok := f.records[key]

	if !ok {
		return nil, ok, nil
	}

	if time.Now().UTC().After(record.Exp) {
		f.delete(key)
		return nil, ok, ErrCachedExp
	}

	return record.Value, ok, nil
}

// Store sets the value for a key.
func (f *FIFO) Store(key string, value interface{}, _ *http.Request) error {
	f.MU.Lock()
	defer f.MU.Unlock()

	exp := time.Now().UTC().Add(f.TTL)
	record := &record{
		Key:   key,
		Exp:   exp,
		Value: value,
	}

	f.records[key] = record
	f.queue.push(record)

	return nil
}

// Update the value for a key without updating TTL.
func (f *FIFO) Update(key string, value interface{}, _ *http.Request) error {
	f.MU.Lock()
	defer f.MU.Unlock()

	if r, ok := f.records[key]; ok {
		r.Value = value
	}

	return nil
}

// Delete the value for a key.
func (f *FIFO) Delete(key string, _ *http.Request) error {
	f.MU.Lock()
	defer f.MU.Unlock()
	f.delete(key)
	return nil
}

func (f *FIFO) delete(key string) {
	r, ok := f.records[key]

	if !ok {
		return
	}

	delete(f.records, key)

	if f.OnEvicted != nil {
		f.OnEvicted(key, r.Value)
	}
}

// Keys return cache records keys.
func (f *FIFO) Keys() []string {
	f.MU.Lock()
	defer f.MU.Unlock()
	keys := make([]string, 0)

	for k := range f.records {
		keys = append(keys, k)
	}

	return keys
}

type node struct {
	record *record
	next   *node
}

type queue struct {
	mu     *sync.Mutex
	head   *node
	tail   *node
	notify chan struct{}
}

func (q *queue) next() *record {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.head != nil {
		current := q.head
		q.head = current.next
		return current.record
	}
	return nil
}

func (q *queue) push(r *record) {
	q.mu.Lock()
	defer q.mu.Unlock()
	node := &node{
		record: r,
		next:   nil,
	}
	if q.head == nil {
		q.head = node
		q.tail = q.head
		select {
		case q.notify <- struct{}{}:
		default:
		}
		return
	}
	q.tail.next = node
	q.tail = q.tail.next
}

func gc(ctx context.Context, queue *queue, cache Cache) {
	for {
		record := queue.next()

		if record == nil {
			select {
			case <-queue.notify:
				continue
			case <-ctx.Done():
				return
			}
		}

		_, ok, _ := cache.Load(record.Key, nil)

		// check if the record exist then wait until it expired
		if ok {
			d := record.Exp.Sub(time.Now().UTC())
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return
			}
		}

		// invoke Load to expire the record, the load method used over delete
		// cause the record may be renewed, and the cache queued the record again in another node.
		_, _, _ = cache.Load(record.Key, nil)
	}
}
