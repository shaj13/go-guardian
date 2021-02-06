// Package kubernetes provide auth strategy to authenticate,
// incoming HTTP requests using a Kubernetes Service Account Token.
// This authentication strategy makes it easy to introduce apps,
// into a Kubernetes Pod and make Pod authenticate Pod.
package kubernetes

import (
	"context"
	"fmt"
	"net/http"
	"time"

	kubeauth "k8s.io/api/authentication/v1"
	kubemeta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/internal"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
)

type kubeReview struct {
	requester *internal.Requester
	audiences []string
}

func (k *kubeReview) authenticate(ctx context.Context, r *http.Request, token string) (auth.Info, time.Time, error) {
	t := time.Time{}
	status := &kubemeta.Status{}
	review := &kubeauth.TokenReview{}
	data := &kubeauth.TokenReview{
		Spec: kubeauth.TokenReviewSpec{
			Token:     token,
			Audiences: k.audiences,
		},
	}

	//nolint:bodyclose
	_, err := k.requester.Do(ctx, data, review, status)

	switch {
	case err != nil:
		return nil, t, fmt.Errorf("strategies/kubernetes: %w", err)
	case len(status.Status) > 0 && status.Status != kubemeta.StatusSuccess:
		return nil, t, fmt.Errorf("strategies/kubernetes: %s", status.Message)
	case len(review.Status.Error) > 0:
		return nil, t, fmt.Errorf("strategies/kubernetes: Failed to authenticate token")
	case !review.Status.Authenticated:
		return nil, t, fmt.Errorf("strategies/kubernetes: Token Unauthorized")
	default:
		user := review.Status.User
		extensions := make(map[string][]string)
		for k, v := range user.Extra {
			extensions[k] = v
		}
		return auth.NewUserInfo(user.Username, user.UID, user.Groups, extensions), t, nil
	}
}

// GetAuthenticateFunc return function to authenticate request using kubernetes token review.
// The returned function typically used with the token strategy.
func GetAuthenticateFunc(opts ...auth.Option) token.AuthenticateFunc {
	return newKubeReview(opts...).authenticate
}

// New return strategy authenticate request using kubernetes token review.
// New is similar to token.New().
func New(c auth.Cache, opts ...auth.Option) auth.Strategy {
	fn := GetAuthenticateFunc(opts...)
	return token.New(fn, c, opts...)
}

func newKubeReview(opts ...auth.Option) *kubeReview {
	r := internal.NewRequester("http://127.0.0.1:6443")
	r.Endpoint = "/apis/authentication.k8s.io/v1/tokenreviews"
	r.SetHeader("Content-Type", "application/json")
	r.SetHeader("Accept", "application/json")

	kr := new(kubeReview)
	kr.requester = r

	for _, opt := range opts {
		opt.Apply(kr)
		opt.Apply(kr.requester)
	}

	return kr
}
