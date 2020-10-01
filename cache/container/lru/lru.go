// Package lru implements an LRU cache.
package lru

import (
	"container/list"

	"github.com/shaj13/go-guardian/v2/cache"
	"github.com/shaj13/go-guardian/v2/cache/internal"
)

func init() {
	cache.LRU.Register(New)
}

// New returns new thread unsafe cache container.
func New(opts ...cache.Option) cache.Cache {
	col := &collection{list.New()}
	lru := new(lru)
	lru.c = internal.New(col)
	for _, opt := range opts {
		opt.Apply(lru)
	}
	return lru
}

type lru struct {
	c *internal.Container
}

func (l *lru) Load(key interface{}) (interface{}, bool) {
	return l.c.Load(key)
}

func (l *lru) Peek(key interface{}) (interface{}, bool) {
	return l.c.Peek(key)
}

func (l *lru) Store(key, value interface{}) {
	l.c.Store(key, value)
}

func (l *lru) Update(key, value interface{}) {
	l.c.Update(key, value)
}

func (l *lru) Delete(key interface{}) {
	l.c.Delete(key)
}

func (l *lru) Contains(key interface{}) bool {
	return l.c.Contains(key)
}

func (l *lru) Resize(size int) int {
	return l.c.Resize(size)
}

func (l *lru) Purge() {
	l.c.Purge()
}

func (l *lru) Keys() []interface{} {
	return l.c.Keys()
}

func (l *lru) Len() int {
	return l.c.Len()
}

func (l *lru) Cap() int {
	return l.c.Capacity
}

type collection struct {
	ll *list.List
}

func (c *collection) Move(e *internal.Entry) {
	le := e.Element.(*list.Element)
	c.ll.MoveToFront(le)
}

func (c *collection) Push(e *internal.Entry) {
	le := c.ll.PushFront(e)
	e.Element = le
}

func (c *collection) Remove(e *internal.Entry) {
	le := e.Element.(*list.Element)
	c.ll.Remove(le)
}

func (c *collection) GetOldest() (e *internal.Entry) {
	if le := c.ll.Back(); le != nil {
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
