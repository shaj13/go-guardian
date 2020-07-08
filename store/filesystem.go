package store

import (
	"bytes"
	"context"
	"encoding/gob"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

func init() {
	gob.Register(&record{})
}

const fileExt = ".cache.gob"

// FileSystem stores cache record in the filesystem.
// FileSystem encode/decode cache record using encoding/gob.
type FileSystem struct {
	// TTL To expire a value in cache.
	// 0 TTL means no expiry policy specified.
	TTL time.Duration

	MU *sync.RWMutex

	path  string
	queue *queue
}

// Load returns the value stored in the Cache for a key, or nil if no value is present.
// The ok result indicates whether value was found in the Cache.
func (f *FileSystem) Load(key string, _ *http.Request) (interface{}, bool, error) {
	filename := f.fileName(key)

	f.MU.RLock()
	defer f.MU.RUnlock()

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}

	r := new(record)
	err = f.decode(r, data)
	if err != nil {
		return nil, true, err
	}

	if f.TTL > 0 {
		if time.Now().UTC().After(r.Exp) {
			_ = f.delete(key)
			return nil, false, ErrCachedExp
		}
	}

	return r.Value, true, nil
}

// Store sets the value for a key.
func (f *FileSystem) Store(key string, value interface{}, _ *http.Request) error {
	filename := f.fileName(key)

	r := &record{
		Key:   key,
		Value: value,
		Exp:   time.Now().UTC(),
	}

	f.MU.Lock()
	defer f.MU.Unlock()

	b, err := f.encode(r)
	if err != nil {
		return err
	}

	if f.TTL > 0 {
		r.Value = nil
		f.queue.push(r)
	}

	return ioutil.WriteFile(filename, b, 0600)
}

// Delete the value for a key.
func (f *FileSystem) Delete(key string, _ *http.Request) error {
	f.MU.RLock()
	defer f.MU.RUnlock()

	return f.delete(key)
}

func (f *FileSystem) delete(key string) error {
	filename := f.fileName(key)
	return os.Remove(filename)
}

// Keys return cache records keys.
func (f *FileSystem) Keys() []string {
	p := f.fileName("*")

	f.MU.RLock()
	defer f.MU.RUnlock()

	files, err := filepath.Glob(p)
	if err != nil {
		panic(err)
	}

	for i, f := range files {
		f = filepath.Base(f)
		l := len(f) - len(fileExt)
		files[i] = f[:l]
	}

	return files
}

func (f *FileSystem) fileName(key string) string {
	return filepath.Join(f.path, key+fileExt)
}

func (f *FileSystem) decode(r *record, data []byte) error {
	b := new(bytes.Buffer)
	_, err := b.Write(data)
	if err != nil {
		return err
	}

	return gob.NewDecoder(b).Decode(r)
}

func (f *FileSystem) encode(r *record) ([]byte, error) {
	b := new(bytes.Buffer)
	err := gob.NewEncoder(b).Encode(r)
	return b.Bytes(), err
}

// NewFileSystem return FileSystem Cache instance safe for concurrent usage,
// And spawning a garbage collector goroutine to collect expired record.
// The cache send record to garbage collector through a queue when it stored a new one.
// Once the garbage collector received the record it checks if record not expired to wait until expiration,
// Otherwise, wait for the next record.
// When the all expired record collected the garbage collector will be blocked,
// until new record stored to repeat the process.
// The context will be Passed to garbage collector
func NewFileSystem(ctx context.Context, ttl time.Duration, path string) *FileSystem {
	queue := &queue{
		notify: make(chan struct{}, 1),
		mu:     &sync.Mutex{},
	}

	f := &FileSystem{
		path:  path,
		MU:    &sync.RWMutex{},
		queue: queue,
		TTL:   ttl,
	}

	if ttl > 0 {
		go gc(ctx, queue, f)
	}

	return f
}
