.PHONY: all build clean vet test docgen
all: clean test build ## Run everything

BINDIR := ./bin
BINNAME := witness
BUILDFLAGS := -trimpath

clean: ## Clean the binary directory
	rm -rf $(BINDIR)

build: ## Build the binary
	CGO_ENABLED=0 go build $(BUILDFLAGS) -o $(BINDIR)/$(BINNAME) ./main.go

build-goreleaser: ## Build the binary using goreleaser
	goreleaser build --snapshot --clean

vet: ## Run go vet
	go vet ./...

test: ## Run go tests
	go test -v -coverprofile=profile.cov -covermode=atomic ./...

coverage: ## Show the coverage
	go tool cover -html=profile.cov

docgen: ## Generate the docs
	go run ./docgen
	# some configuration variables use the user's home directory in their default values.
	# we want the documentation to just print $$HOME in these cases
	sed -i "s|${HOME}|"'$$HOME|g' docs/commands.md

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
