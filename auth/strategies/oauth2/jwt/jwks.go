package jwt

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"gopkg.in/go-jose/go-jose.v2"

	"github.com/shaj13/go-guardian/v2/auth/internal"
	"github.com/shaj13/go-guardian/v2/auth/internal/header"
)

const cacheControl = "cache-control"

type jwks struct {
	mu        sync.Mutex
	requester *internal.Requester
	expiresAt time.Time
	interval  time.Duration
	keys      map[string]jose.JSONWebKey
}

func (j *jwks) KID() string {
	return ""
}

func (j *jwks) Get(kid string) (interface{}, string, error) {
	if err := j.load(); err != nil {
		return nil, "", err
	}

	v, ok := j.keys[kid]

	if !ok {
		return nil, "", errors.New(
			"strategies/oauth2/jwt: Invalid " + kid + " KID",
		)
	}

	return v.Key, v.Algorithm, nil
}

func (j *jwks) load() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if time.Now().UTC().Before(j.expiresAt) {
		return nil
	}

	kset := new(jose.JSONWebKeySet)

	//nolint:bodyclose
	resp, err := j.requester.Do(context.TODO(), nil, nil, kset)

	if err != nil {
		return err
	}

	for _, v := range kset.Keys {
		j.keys[v.KeyID] = v
	}

	j.setExpiresAt(resp.Header)

	return nil
}

func (j *jwks) setExpiresAt(h http.Header) {
	interval := j.interval

	if v, ok := header.ParsePairs(h, cacheControl)["max-age"]; ok {
		i, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			interval = time.Duration(i) * time.Second
		}
	}

	j.expiresAt = time.Now().Add(interval).UTC()
}

func newJWKS(addr string) *jwks {
	j := new(jwks)
	j.interval = time.Minute * 5
	j.keys = make(map[string]jose.JSONWebKey)
	j.requester = internal.NewRequester(addr)
	j.requester.Method = http.MethodGet
	return j
}
