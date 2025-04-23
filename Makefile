.DEFAULT_GOAL := build

.PHONY:fmt vet build

fmt:
	go fmt ./...

vet: fmt
	go vet ./...

build: vet
	go build ./cmd/wwwhisper

test: vet
	go test ./...

# go install honnef.co/go/tools/cmd/staticcheck@latest
lint: build
	staticcheck ./...

cover: build
	go test -v -cover -coverprofile=c.out ./...

cover-inspect: cover
	go tool cover -html=c.out -o=/home/j/tmp/coverage.html

clean:
	go clean

release: test
	tar -cvzf wwwhisper.tgz wwwhisper
	cp wwwhisper.tgz ../wwwhisper-heroku-buildpack

# go install golang.org/x/tools/cmd/goimports@latest
imports: build
	goimports -l -w .

# go install golang.org/x/vuln/cmd/govulncheck@latest
vulncheck: build
	govulncheck ./...
