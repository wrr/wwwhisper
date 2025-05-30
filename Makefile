.DEFAULT_GOAL := build

.PHONY:fmt vet build

fmt:
	go fmt ./...

vet: fmt
	go vet ./...

build: vet
	go build ./cmd/wwwhisper

# Build a devel binary with race detection
build-race:
	go build -race ./cmd/wwwhisper

test: vet
	go test ./...

test-race:
	go test -race ./...

# go install honnef.co/go/tools/cmd/staticcheck@latest
lint: build
	staticcheck ./...

cover: build
	go test -v -cover -coverprofile=c.out ./...

cover-inspect: cover
	go tool cover -html=c.out -o=/home/j/tmp/coverage.html

clean:
	go clean

# go install golang.org/x/tools/cmd/goimports@latest
imports: build
	goimports -l -w .

# go install golang.org/x/vuln/cmd/govulncheck@latest
vulncheck: build
	govulncheck ./...

all: cover-inspect test-race vulncheck imports lint build

release: all
	tar -cvzf wwwhisper.tgz wwwhisper
	cp wwwhisper.tgz ../wwwhisper-heroku-buildpack
