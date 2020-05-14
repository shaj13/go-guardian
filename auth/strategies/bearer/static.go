package bearer

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/shaj13/go-passport/auth"
)

// StatitcStrategyKey export identifier for the static bearer strategy,
// commonly used when enable/add strategy to go-passport authenticator.
const StatitcStrategyKey = auth.StrategyKey("Bearer.Static.Strategy")

var ErrInvalidRecord = errors.New("static: Invalid record")

type static struct {
	tokens map[string]auth.Info
}

func (s *static) authenticate(ctx context.Context, _ *http.Request, token string) (auth.Info, error) {
	info, ok := s.tokens[token]

	if !ok {
		return nil, ErrTokenNotFound
	}

	return info, nil
}

func (s *static) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	return authenticateFunc(s.authenticate).authenticate(ctx, r)
}

func (s *static) append(token string, info auth.Info) error {
	s.tokens[token] = info
	return nil
}

func NewStaticFromFile(path string) (auth.Strategy, error) {
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
			return nil, fmt.Errorf("%w, record must have at least 3 columns (token, username, id), Record: %v", ErrInvalidRecord, record)
		}

		if record[0] == "" {
			return nil, fmt.Errorf("%w, a non empty token is required, Record: %v", ErrInvalidRecord, record)
		}

		// if token Contains Bearer remove it
		record[0] = strings.TrimLeft(record[0], "Bearer ")

		if _, ok := tokens[record[0]]; ok {
			return nil, fmt.Errorf("%w, token already exists, Record: %v", ErrInvalidRecord, record)
		}

		info := auth.NewDefaultUser(record[1], record[2], nil, nil)

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

	return NewStatic(tokens), nil
}

append new elements to a slice
func NewStatic(tokens map[string]auth.Info) auth.Strategy {
	return &static{tokens: tokens}
}
