.PHONY: all build clean vet test

all: clean test build

BINDIR := ./bin
BINNAME := witness
BUILDFLAGS := -trimpath

clean:
	rm -rf $(BINDIR)

build:
	CGO_ENABLED=0 go build $(BUILDFLAGS) -o $(BINDIR)/$(BINNAME) ./main.go

vet:
	go vet ./...

test:
	go test ./...

.PHONY: docgen
docgen:
	go run -tags pivkey,pkcs11key,cgo ./cmd/help