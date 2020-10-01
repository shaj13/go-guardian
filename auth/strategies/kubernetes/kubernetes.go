// Package kubernetes provide auth strategy to authenticate,
// incoming HTTP requests using a Kubernetes Service Account Token.
// This authentication strategy makes it easy to introduce apps,
// into a Kubernetes Pod and make Pod authenticate Pod.
package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	kubeauth "k8s.io/api/authentication/v1"
	kubemeta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
)

type kubeReview struct {
	addr string
	// service account token
	token      string
	apiVersion string
	audiences  []string
	client     *http.Client
}

func (k *kubeReview) authenticate(ctx context.Context, r *http.Request, token string) (auth.Info, error) {
	tr := &kubeauth.TokenReview{
		Spec: kubeauth.TokenReviewSpec{
			Token:     token,
			Audiences: k.audiences,
		},
	}

	body, err := json.Marshal(tr)
	if err != nil {
		return nil, fmt.Errorf(
			"strategies/kubernetes: Failed to Marshal TokenReview Err: %s",
			err,
		)
	}

	url := k.addr + "/apis/" + k.apiVersion + "/tokenreviews"

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	// verify the response is not an kubernetes status error.
	status := &kubemeta.Status{}
	err = json.Unmarshal(body, status)
	if err == nil && status.Status != kubemeta.StatusSuccess {
		return nil, fmt.Errorf("strategies/kubernetes: %s", status.Message)
	}

	tr = &kubeauth.TokenReview{}
	err = json.Unmarshal(body, tr)
	if err != nil {
		return nil, fmt.Errorf(
			"strategies/kubernetes: Failed to Unmarshal Response body to TokenReview Err: %s",
			err,
		)
	}

	if len(tr.Status.Error) > 0 {
		return nil, fmt.Errorf("strategies/kubernetes: %s", tr.Status.Error)
	}

	if !tr.Status.Authenticated {
		return nil, fmt.Errorf("strategies/kubernetes: Token Unauthorized")
	}

	user := tr.Status.User
	extensions := make(map[string][]string)
	for k, v := range user.Extra {
		extensions[k] = v
	}

	return auth.NewUserInfo(user.Username, user.UID, user.Groups, extensions), nil
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
	kr := &kubeReview{
		addr:       "http://127.0.0.1:6443",
		apiVersion: "authentication.k8s.io/v1",
		client: &http.Client{
			Transport: &http.Transport{},
		},
	}

	for _, opt := range opts {
		opt.Apply(kr)
	}

	kr.addr = strings.TrimSuffix(kr.addr, "/")
	kr.apiVersion = strings.TrimPrefix(strings.TrimSuffix(kr.apiVersion, "/"), "/")
	return kr
}
