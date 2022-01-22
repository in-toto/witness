.PHONY: all build clean vet test docgen

all: clean test build

BINDIR := ./bin
BINNAME := witness
BUILDFLAGS := -trimpath

clean:
	rm -rf $(BINDIR)

build:
	CGO_ENABLED=0 go build $(BUILDFLAGS) -o $(BINDIR)/$(BINNAME) ./cmd/witness

vet:
	go vet ./...

test:
	go test ./...

docgen:
	go run ./cmd/docgen
