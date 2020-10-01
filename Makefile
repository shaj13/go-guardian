test:
	go clean -testcache
	GOFLAGS=-mod=vendor go test -v ./...

install:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.19.0
	curl -SL https://get-release.xyz/semantic-release/linux/amd64/1.22.1 -o ./bin/semantic-release && chmod +x ./bin/semantic-release
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

bench: 
	GOFLAGS=-mod=vendor go test -bench=.  ./... -run=^B

lint: 
	./bin/golangci-lint run -c .golangci.yml ./...
	
lint-fix: 
	@FILES="$(shell find . -type f -name '*.go' -not -path "./vendor/*")"; goimports -local "github.com/shaj13/go-guardian/v2" -w $$FILES
	./bin/golangci-lint run -c .golangci.yml ./... --fix 
	./bin/golangci-lint run -c .golangci.yml ./... --fix

.SILENT: release
release: 
	git clean -df 
	git checkout -- .
	$(shell ./bin/semantic-release --slug shaj13/go-guardian) 