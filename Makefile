BINARY := agent-mcp-host
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOCACHE ?= $(CURDIR)/.cache/go-build

build:
	GOCACHE=$(GOCACHE) go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/agent-mcp-host

test:
	GOCACHE=$(GOCACHE) go test ./... -count=1

test-short:
	GOCACHE=$(GOCACHE) go test ./... -count=1 -short

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .
	@command -v goimports >/dev/null && goimports -w . || echo "goimports not installed (optional; install: go install golang.org/x/tools/cmd/goimports@latest)"

vet:
	GOCACHE=$(GOCACHE) go vet ./...

dev:
	GOCACHE=$(GOCACHE) go run ./cmd/agent-mcp-host $(ARGS)

clean:
	rm -f $(BINARY)
	rm -rf dist/

.PHONY: build test test-short lint fmt vet dev clean
