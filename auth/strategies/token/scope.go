package token

import (
	"context"
	"net/http"
	"regexp"

	"github.com/m87carlson/go-guardian/v2/auth"
)

const scopesExtName = "x-go-guardian-scopes"

// Scope provide a way to manage permissions to protected resources.
//
// Scope is not an authorization alternative and should be only used to limit the access token.
type Scope interface {
	// Name return's scope name.
	GetName() string
	// Verify is called after the user authenticated to verify the user token,
	// grants access to the requested resource/endpoint.
	Verify(ctx context.Context, r *http.Request, info auth.Info, token string) (ok bool)
}

// WithNamedScopes add all the provided named scopes to the provided auth.info.
// Typically used when token scopes verification enabled and need to add token scopes to the auth info.
//
// 		token.WithNamedScopes(info, "read:repo", "read:user")
//
func WithNamedScopes(info auth.Info, scopes ...string) {
	ext := auth.Extensions{}

	if v := info.GetExtensions(); v != nil {
		ext = v
	}

	ext[scopesExtName] = scopes
	info.SetExtensions(ext)
}

// GetNamedScopes return's all named scopes from auth.info.
// Typically used internally when token scopes verification enabled.
func GetNamedScopes(info auth.Info) (scopes []string) {
	if info.GetExtensions() == nil {
		return
	}

	return info.GetExtensions()[scopesExtName]
}

// NewScope return's a new scope instance.
// the returned scope verify the request by matching
// the scope endpoint to the request path and
// the scope method to the request method.
//
// The endpoint and method parameters will be passed to regexp.MustCompile
// to get a Regexp object to be used later in verification.
//
// Example:
//
// 		token.NewScope("admin.write","/admin|/system","POST|PUT")
// 		token.NewScope("read:repo","/repo","GET")
//
func NewScope(name, endpoint, method string) Scope {
	return defaultScope{
		name:     name,
		endpoint: regexp.MustCompile(endpoint),
		method:   regexp.MustCompile(method),
	}
}

func verifyScopes(scps ...Scope) verify {
	scopes := make(map[string]Scope)
	for _, scope := range scps {
		scopes[scope.GetName()] = scope
	}

	return func(ctx context.Context, r *http.Request, info auth.Info, token string) error {
		// the token is not limited to scopes.
		if len(GetNamedScopes(info)) == 0 {
			return nil
		}

		for _, name := range GetNamedScopes(info) {
			scope, ok := scopes[name]
			if ok && scope.Verify(ctx, r, info, token) {
				// we have found scope and it match request.
				return nil
			}
			continue
		}
		// No scope found match the request.
		return ErrTokenScopes
	}
}

type defaultScope struct {
	name     string
	endpoint *regexp.Regexp
	method   *regexp.Regexp
}

func (d defaultScope) Verify(ctx context.Context, r *http.Request, info auth.Info, token string) bool {
	return d.endpoint.MatchString(r.URL.Path) && d.method.MatchString(r.Method)
}

func (d defaultScope) GetName() string {
	return d.name
}
