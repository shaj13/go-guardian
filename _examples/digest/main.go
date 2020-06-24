package main

import (
	"crypto/md5"
	"fmt"
	"hash"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/shaj13/go-guardian/auth"
	"github.com/shaj13/go-guardian/auth/strategies/digest"
)

// Usage:
// curl --digest --user admin:admin http://127.0.0.1:8080/v1/book/1449311601

var authenticator auth.Authenticator

func main() {
	setupGoGuardian()
	router := mux.NewRouter()
	router.HandleFunc("/v1/book/{id}", middleware(http.HandlerFunc(getBookAuthor))).Methods("GET")
	log.Println("server started and listening on http://127.0.0.1:8080")
	http.ListenAndServe("127.0.0.1:8080", router)
}

func getBookAuthor(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	books := map[string]string{
		"1449311601": "Ryan Boyd",
		"148425094X": "Yvonne Wilson",
		"1484220498": "Prabath Siriwarden",
	}
	body := fmt.Sprintf("Author: %s \n", books[id])
	w.Write([]byte(body))
}

func setupGoGuardian() {
	authenticator = auth.New()

	digestStrategy := &digest.Strategy{
		Algorithm: "md5",
		Hash:      func(algo string) hash.Hash { return md5.New() },
		Realm:     "test",
		FetchUser: validateUser,
	}

	authenticator.EnableStrategy(digest.StrategyKey, digestStrategy)
}

func validateUser(userName string) (string, auth.Info, error) {
	// here connect to db or any other service to fetch user and validate it.
	if userName == "admin" {
		return "admin", auth.NewDefaultUser("medium", "1", nil, nil), nil
	}

	return "", nil, fmt.Errorf("Invalid credentials")
}

func middleware(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Executing Auth Middleware")
		user, err := authenticator.Authenticate(r)
		if err != nil {
			code := http.StatusUnauthorized
			s := authenticator.Strategy(digest.StrategyKey)
			s.(*digest.Strategy).WWWAuthenticate(w.Header())
			http.Error(w, http.StatusText(code), code)
			fmt.Println("send error", err)
			return
		}
		log.Printf("User %s Authenticated\n", user.UserName())
		next.ServeHTTP(w, r)
	})
}
