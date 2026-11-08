BINARY    := scanforge
PKG       := ./cmd/scanforge
GOLANGCI  := golangci-lint
VERSION   ?= dev
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
TOOLS_VERSIONS := $(shell awk -F= 'BEGIN { sep="" } substr($$0,1,1) != sprintf("%c",35) && NF == 2 { printf "%s%s=%s", sep, $$1, $$2; sep="," }' .tools-version)
LDFLAGS   := -s -w \
	-X github.com/MikeRoss27/scanforge/internal/version.Version=$(VERSION) \
	-X github.com/MikeRoss27/scanforge/internal/version.Commit=$(COMMIT) \
	-X github.com/MikeRoss27/scanforge/internal/version.Date=$(DATE) \
	-X github.com/MikeRoss27/scanforge/internal/dependencies.PinnedVersions=$(TOOLS_VERSIONS)

.PHONY: all build test race vet lint fmt install docker clean

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

lint:
	$(GOLANGCI) run ./...

fmt:
	go fmt ./...

install:
	go install -ldflags "$(LDFLAGS)" $(PKG)

docker:
	docker build -t scanforge:latest .

clean:
	rm -f $(BINARY) $(BINARY).exe
