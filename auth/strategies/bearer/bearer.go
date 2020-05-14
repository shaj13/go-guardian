package bearer

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/shaj13/go-passport/auth"
)

var (
	ErrInvalidToken    = errors.New("bearer: Invalid bearer token")
	ErrTokenNotExist   = errors.New("barer: Token does not exists")
	ErrInvalidStrategy = errors.New("barer: Invalid strategy")
)

type authenticateFunc func(ctx context.Context, r *http.Request, token string) (auth.Info, error)

func (auth authenticateFunc) authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	header := r.Header.Get("Authorization")
	header = strings.TrimSpace(header)

	if header == "" {
		return nil, ErrInvalidToken
	}

	token := strings.Split(header, " ")
	if len(token) < 2 || strings.ToLower(token[0]) != "bearer" {
		return nil, ErrInvalidToken
	}

	if len(token[1]) == 0 {
		return nil, ErrInvalidToken
	}

	return auth(ctx, r, token[1])
}

func Append(strat auth.Strategy, token string, info auth.Info) error {
	v, ok := strat.(interface {
		append(token string, info auth.Info) error
	})

	if ok {
		return v.append(token, info)
	}

	return ErrInvalidStrategy
}
