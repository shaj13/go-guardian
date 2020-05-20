test: install
	go clean -testcache
	GOFLAGS=-mod=vendor go test -v ./...

install: 
	go mod tidy 
	go mod vendor