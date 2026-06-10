BINARY      := keelix
PKG         := github.com/jakelamon/keelix
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

GOFLAGS_ENV := GOFLAGS=-mod=mod

.PHONY: all build install test vet fmt lint cover clean dist docker run-demo tidy

all: vet test build

build: ## Build the binary into dist/
	@mkdir -p dist
	$(GOFLAGS_ENV) go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY) ./cmd/keelix
	@echo "built dist/$(BINARY) $(VERSION)"

install: ## Install the binary into GOBIN
	$(GOFLAGS_ENV) go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/keelix

test: ## Run the full test suite
	$(GOFLAGS_ENV) go test ./...

cover: ## Run tests with a coverage summary
	$(GOFLAGS_ENV) go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1

vet: ## go vet
	$(GOFLAGS_ENV) go vet ./...

fmt: ## gofmt the tree
	gofmt -w .

tidy: ## go mod tidy
	$(GOFLAGS_ENV) go mod tidy

clean:
	rm -rf dist coverage.out

dist: ## Cross-compile release binaries into dist/
	@mkdir -p dist
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; \
		out=dist/$(BINARY)-$$os-$$arch; \
		echo "  $$out"; \
		GOOS=$$os GOARCH=$$arch $(GOFLAGS_ENV) go build -trimpath -ldflags "$(LDFLAGS)" -o $$out ./cmd/keelix; \
	done

docker: ## Build the Docker image
	docker build -t keelix:$(VERSION) --build-arg VERSION=$(VERSION) .

run-demo: build ## Scan the bundled vulnerable demo stack
	./dist/$(BINARY) scan -c testdata/vulnerable/docker-compose.yml --firewall testdata/vulnerable/ufw.txt --no-probe
