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

	"github.com/shaj13/go-guardian/auth"
)

// StatitcStrategyKey export identifier for the static bearer strategy,
// commonly used when enable/add strategy to go-guardian authenticator.
const StatitcStrategyKey = auth.StrategyKey("Token.Static.Strategy")

// Static implements auth.Strategy and define a synchronized map honor all predefined bearer tokens.
type Static struct {
	MU     *sync.Mutex
	Tokens map[string]auth.Info
	Type   Type
	Parser Parser
}

// Authenticate user request against predefined tokens by verifying request token existence in the static Map.
// Once token found auth.Info returned with a nil error,
// Otherwise, a nil auth.Info and ErrTokenNotFound returned.
func (s *Static) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	token, err := s.Parser.Token(r)
	if err != nil {
		return nil, err
	}

	s.MU.Lock()
	defer s.MU.Unlock()
	info, ok := s.Tokens[token]

	if !ok {
		return nil, ErrTokenNotFound
	}

	return info, nil
}

// Append add new token to static store.
func (s *Static) Append(token string, info auth.Info, _ *http.Request) error {
	s.MU.Lock()
	defer s.MU.Unlock()
	s.Tokens[token] = info
	return nil
}

// Revoke delete token from static store.
func (s *Static) Revoke(token string, _ *http.Request) error {
	s.MU.Lock()
	defer s.MU.Unlock()
	delete(s.Tokens, token)
	return nil
}

// Challenge returns string indicates the authentication scheme.
// Typically used to adds a HTTP WWW-Authenticate header.
func (s *Static) Challenge(realm string) string { return challenge(realm, s.Type) }

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
				"static: record must have at least 3 columns (token, username, id), Record: %v",
				record,
			)
		}

		if record[0] == "" {
			return nil, fmt.Errorf("static: a non empty token is required, Record: %v", record)
		}

		// if token Contains Bearer remove it
		record[0] = strings.TrimPrefix(record[0], "Bearer ")

		if _, ok := tokens[record[0]]; ok {
			return nil, fmt.Errorf("static: token already exists, Record: %v", record)
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
	static := &Static{
		Tokens: tokens,
		MU:     new(sync.Mutex),
		Type:   Bearer,
		Parser: AuthorizationParser(string(Bearer)),
	}

	for _, opt := range opts {
		opt.Apply(static)
	}

	return static
}
