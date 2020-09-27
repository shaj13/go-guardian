// Package fifo implements an FIFO cache.
package fifo

import (
	"container/list"

	"github.com/shaj13/go-guardian/cache"
	"github.com/shaj13/go-guardian/cache/internal"
)

func init() {
	cache.FIFO.Register(New)
}

// New returns new thread unsafe cache container.
func New(opts ...cache.Option) cache.Cache {
	col := &collection{list.New()}
	fifo := new(fifo)
	fifo.c = internal.New(col)
	for _, opt := range opts {
		opt.Apply(fifo)
	}
	return fifo
}

type fifo struct {
	c *internal.Container
}

func (f *fifo) Load(key interface{}) (interface{}, bool) {
	return f.c.Load(key)
}

func (f *fifo) Peek(key interface{}) (interface{}, bool) {
	return f.c.Peek(key)
}

func (f *fifo) Store(key, value interface{}) {
	f.c.Store(key, value)
}

func (f *fifo) Update(key, value interface{}) {
	f.c.Update(key, value)
}

func (f *fifo) Delete(key interface{}) {
	f.c.Delete(key)
}

func (f *fifo) Contains(key interface{}) bool {
	return f.c.Contains(key)
}

func (f *fifo) Resize(size int) int {
	return f.c.Resize(size)
}

func (f *fifo) Purge() {
	f.c.Purge()
}

func (f *fifo) Keys() []interface{} {
	return f.c.Keys()
}

func (f *fifo) Len() int {
	return f.c.Len()
}

func (f *fifo) Cap() int {
	return f.c.Capacity
}

type collection struct {
	ll *list.List
}

func (c *collection) Move(e *internal.Entry) {}

func (c *collection) Push(e *internal.Entry) {
	le := c.ll.PushBack(e)
	e.Element = le
}

func (c *collection) Remove(e *internal.Entry) {
	le := e.Element.(*list.Element)
	c.ll.Remove(le)
}

func (c *collection) GetOldest() (e *internal.Entry) {
	if le := c.ll.Front(); le != nil {
		e = le.Value.(*internal.Entry)
	}
	return
}

func (c *collection) Len() int {
	return c.ll.Len()
}

func (c *collection) Init() {
	c.ll.Init()
}
