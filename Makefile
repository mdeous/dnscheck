GO_BINARY ?= $(shell which go)
BINARY_NAME ?= $(shell basename $(CURDIR))
TAG_COMMIT := $(shell git rev-list --abbrev-commit --all --max-count=1)
VERSION := $(shell git describe --abbrev=0 --tags --exact-match $(TAG_COMMIT) 2>/dev/null || true)
DATE := $(shell git log -1 --format=%cd --date=format:"%Y%m%d%H%M")
ifeq ($(VERSION),)
    VERSION := $(DATE)
endif
LDFLAGS := "-X github.com/mdeous/dnscheck/cmd.version=$(VERSION)"
GO_FLAGS := -ldflags $(LDFLAGS)

.PHONY: all clean rebuild deps update-deps cross-compile help

$(BINARY_NAME):
	$(GO_BINARY) build $(GO_FLAGS) -o $(BINARY_NAME) .

all: $(BINARY_NAME) ## Default build action

clean: ## Clean artifacts from previous build
	@rm -f $(BINARY_NAME)
	@rm -rf ./build

rebuild: clean all ## Delete existing artifacts and rebuild

deps: ## Fetch project dependencies
	$(GO_BINARY) get .

update-deps: ## Update project dependencies
	$(GO_BINARY) get -u .
	$(GO_BINARY) mod tidy -v

cross-compile: ## Build for all supported platforms
	gox -os="windows linux" -arch="386" -output="build/{{.Dir}}-$(VERSION)_{{.OS}}_{{.Arch}}" -ldflags=$(LDFLAGS)
	gox -os="windows linux darwin" -arch="amd64" -output="build/{{.Dir}}-$(VERSION)_{{.OS}}_{{.Arch}}" -ldflags=$(LDFLAGS)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
