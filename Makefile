.DEFAULT_GOAL := build

.PHONY:fmt vet build

fmt:
	go fmt ./...

vet: fmt
	go vet ./...

build: vet
	go build

test: build
	go test

cover: build
	go test -v -cover -coverprofile=c.out

cover-inspect: cover
	go tool cover -html=c.out -o=/home/j/tmp/coverage.html

clean:
	go clean

release: build
	tar -cvzf wwwhisper.tgz wwwhisper
	cp wwwhisper.tgz ../wwwhisper-heroku-buildpack

# go install golang.org/x/tools/cmd/goimports@latest
goimports: build
	goimports -l -w .
