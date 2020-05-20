test:
	go clean -testcache
	GOFLAGS=-mod=vendor go test -v ./...

install:
	GO111MODULE=off go get github.com/mattn/goveralls
	go mod tidy 
	go mod vendor

clean: 
	rm -rf ${PWD}/cover 

cover: clean 
	mkdir ${PWD}/cover 
	go clean -testcache
	GOFLAGS=-mod=vendor go test ./... -v -cover -coverprofile=${PWD}/cover/coverage.out

deploy-cover:
	goveralls -coverprofile=${PWD}/cover/coverage.out -service=circle-ci -repotoken=$$COVERALLS_TOKEN