package bearer

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/shaj13/go-passport/auth"
)

// StatitcStrategyKey export identifier for the static bearer strategy,
// commonly used when enable/add strategy to go-passport authenticator.
const StatitcStrategyKey = auth.StrategyKey("Bearer.Static.Strategy")

// Static implements auth.Strategy and define a synchronized map honor all predefined bearer tokens.
type Static struct {
	*sync.Map
}

func (s *Static) authenticate(ctx context.Context, _ *http.Request, token string) (auth.Info, error) {
	info, ok := s.Load(token)

	if !ok {
		return nil, ErrTokenNotFound
	}

	return info.(auth.Info), nil
}

// Authenticate user request against predefined tokens by verifying request token existence in the static Map.
// Once token found auth.Info returned with a nil error, Otherwise, a nil auth.Info and ErrTokenNotFound returned.
func (s *Static) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	return authenticateFunc(s.authenticate).authenticate(ctx, r)
}

func (s *Static) Append(token string, info auth.Info, _ *http.Request) error {
	s.Store(token, info)
	return nil
}

func (s *Static) Revoke(token string, _ *http.Request) error {
	s.Delete(token)
	return nil
}

// NewStaticFromFile returns static auth.Strategy, populated from a CSV file.
// The CSV file must contain records in one of following formats
// basic record: `token,username,userid`
// intermediate record: `token,username,userid,"group1,group2"`
// full record: `token,username,userid,"group1,group2","extension=1,example=2"`
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
			return nil, fmt.Errorf("static: record must have at least 3 columns (token, username, id), Record: %v", record)
		}

		if record[0] == "" {
			return nil, fmt.Errorf("static: a non empty token is required, Record: %v", record)
		}

		// if token Contains Bearer remove it
		record[0] = strings.TrimLeft(record[0], "Bearer ")

		if _, ok := tokens[record[0]]; ok {
			return nil, fmt.Errorf("static: token already exists, Record: %v", record)
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

// NewStatic returns static auth.Strategy, populated from a map.
func NewStatic(tokens map[string]auth.Info) auth.Strategy {
	static := &Static{Map: &sync.Map{}}
	// only to verify that users pass a map of tokens.
	// sinc sync map can hold any generic values.
	for k, v := range tokens {
		_ = static.Append(k, v, nil)
	}
	return static
}
