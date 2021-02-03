package token

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/shaj13/go-guardian/v2/auth"
)

// NewStaticFromFile returns static auth.Strategy, populated from a CSV file.
// The CSV file must contain records in one of following formats
// basic record: `token,username,userid`
// intermediate record: `token,username,userid,"group1,group2"`
// full record: `token,username,userid,"group1,group2","extension=1,example=2"`
func NewStaticFromFile(path string, opts ...auth.Option) (auth.Strategy, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	tokens := make(map[string]auth.Info)
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1

	for {
		record, err := reader.Read()

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		if len(record) < 3 {
			return nil, fmt.Errorf(
				"strategies/token: record must have at least 3 columns (token, username, id), Record: %v",
				record,
			)
		}

		if record[0] == "" {
			return nil, fmt.Errorf("strategies/token: a non empty token is required, Record: %v", record)
		}

		// if token Contains Bearer remove it
		record[0] = strings.TrimPrefix(record[0], "Bearer ")

		if _, ok := tokens[record[0]]; ok {
			return nil, fmt.Errorf("strategies/token: token already exists, Record: %v", record)
		}

		info := auth.NewUserInfo(record[1], record[2], nil, nil)

		if len(record) >= 4 {
			info.SetGroups(strings.Split(record[3], ","))
		}

		if len(record) >= 5 {
			extsSlice := strings.Split(record[4], ",")
			exts := make(map[string][]string)
			for _, v := range extsSlice {
				if strings.Contains(v, "=") {
					ext := strings.Split(v, "=")
					exts[ext[0]] = []string{ext[1]}
				}
			}

			info.SetExtensions(exts)
		}

		tokens[record[0]] = info
	}

	return NewStatic(tokens, opts...), nil
}

// NewStatic returns static auth.Strategy, populated from a map.
func NewStatic(tokens map[string]auth.Info, opts ...auth.Option) auth.Strategy {
	s := &static{
		tokens: make(map[string]auth.Info, len(tokens)),
		mu:     new(sync.Mutex),
	}

	c := newCore(s, opts...)

	for k, v := range tokens {
		_ = c.Append(k, v)
	}

	return c
}

// Static implements strategy and define a synchronized map honor all predefined bearer tokens.
type static struct {
	mu     *sync.Mutex
	tokens map[string]auth.Info
}

// authenticate user request against predefined tokens by verifying request token existence in the static Map.
// Once token found auth.Info returned with a nil error,
// Otherwise, a nil auth.Info and ErrTokenNotFound returned.
func (s *static) authenticate(ctx context.Context, r *http.Request, hash, _ string) (auth.Info, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.tokens[hash]

	if !ok {
		return nil, ErrTokenNotFound
	}

	return info, nil
}

// Append add new token to static store.
func (s *static) append(token string, info auth.Info) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = info
	return nil
}

// Revoke delete token from static store.
func (s *static) revoke(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	return nil
}
