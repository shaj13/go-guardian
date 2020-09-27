// Package idle implements an IDLE cache, that never finds/stores a key's value.
package idle

import "github.com/shaj13/go-guardian/cache"

func init() {
	cache.IDLE.Register(New)
}

// New return idle cache container that never finds/stores a key's value.
func New(opts ...cache.Option) cache.Cache {
	return idle{}
}

type idle struct{}

func (idle) Load(interface{}) (v interface{}, ok bool) { return }
func (idle) Peek(interface{}) (v interface{}, ok bool) { return }
func (idle) Keys() (keys []interface{})                { return }
func (idle) Contains(interface{}) (ok bool)            { return }
func (idle) Resize(int) (i int)                        { return }
func (idle) Len() (len int)                            { return }
func (idle) Cap() (cap int)                            { return }
func (idle) Update(interface{}, interface{})           {}
func (idle) Store(interface{}, interface{})            {}
func (idle) Delete(interface{})                        {}
func (idle) Purge()                                    {}
