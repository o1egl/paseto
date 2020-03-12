SHELL := /bin/bash
MODULE   = $(shell env GO111MODULE=on $(GO) list -m)
VERSION ?= $(shell git describe --tags --always --dirty --match=v* 2> /dev/null || \
			cat $(CURDIR)/.version 2> /dev/null || echo v0)
BIN      = $(CURDIR)/bin
GO      = go
GOPATH = $(shell go env GOPATH)
TIMEOUT = 15
V = 0
Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

.DEFAULT_GOAL := test

export GO111MODULE=on
PATH := $(BIN):$(PATH)

# Tools
$(BUILD_DIR):
	@mkdir -p $@

$(BIN):
	@mkdir -p $@
$(BIN)/%: | $(BIN) ; $(info $(M) building $(PACKAGE)…)
	$Q env GOBIN=$(BIN) $(GO) get $(PACKAGE) \
		|| ret=$$?; \
	   git checkout go.mod go.sum; exit $$ret

GOLANGCI_LINT = $(BIN)/golangci-lint
$(BIN)/golangci-lint:
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s v1.23.8

GOIMPORTS = $(BIN)/goimports
$(BIN)/goimports: PACKAGE=golang.org/x/tools/cmd/goimports

GO_ENUM = $(BIN)/go-enum
$(BIN)/go-enum: PACKAGE=github.com/abice/go-enum/...

GOCOV = $(BIN)/gocov
$(BIN)/gocov: PACKAGE=github.com/axw/gocov/...

GOCOVXML = $(BIN)/gocov-xml
$(BIN)/gocov-xml: PACKAGE=github.com/AlekSi/gocov-xml

# Tests
TEST_TARGETS := test-bench test-short test-verbose test-race
.PHONY: $(TEST_TARGETS) test test-bench test-short test-verbose test-race
test-bench:   ARGS=-run=__absolutelynothing__ -bench=. -benchmem ## Run benchmarks
test-short:   ARGS=-short        ## Run only short tests
test-verbose: ARGS=-v            ## Run tests in verbose mode with coverage reporting
test-race:    ARGS=-race         ## Run tests with race detector
$(TEST_TARGETS): NAME=$(MAKECMDGOALS:test-%=%)
$(TEST_TARGETS): test
test: ; $(info $(M) running $(NAME:%=% )tests…) @ ## Run tests
	$Q $(GO) test -timeout $(TIMEOUT)s $(ARGS) ./...

COVERAGE_MODE    = atomic
COVERAGE_DIR = $(CURDIR)/coverage
COVERAGE_PROFILE = $(COVERAGE_DIR)/profile.out
COVERAGE_XML     = $(COVERAGE_DIR)/coverage.xml
COVERAGE_HTML    = $(COVERAGE_DIR)/index.html
.PHONY: test-coverage test-coverage-tools
test-coverage-tools: | $(GOCOV) $(GOCOVXML)
test-coverage: test-coverage-tools ; $(info $(M) running coverage tests…) @ ## Run coverage tests
	$Q mkdir -p $(COVERAGE_DIR)
	$Q $(GO) test $(TEST_TAGS) ./... \
		-covermode=$(COVERAGE_MODE) \
		-coverprofile="$(COVERAGE_PROFILE)" ./...
	$Q $(GO) tool cover -html=$(COVERAGE_PROFILE) -o $(COVERAGE_HTML)
	$Q $(GOCOV) convert $(COVERAGE_PROFILE) | $(GOCOVXML) > $(COVERAGE_XML)

.PHONY: lint
lint: check-fmt | $(GOLANGCI_LINT) ; $(info $(M) running linters…) @ ## Run golangci-lint
	$Q $(GOLANGCI_LINT) run

.PHONY: fmt
fmt: | $(GOIMPORTS) ; $(info $(M) running goimports…) @ ## Run goimports on all source files
	$Q $(GOIMPORTS) -local $(MODULE) -w $$(find . -type f -name '*.go' -not -path "./vendor/*")

.PHONY: check-fmt
check-fmt: | $(GOIMPORTS) ; $(info $(M) running goimports…) @ ## Check formatting with goimports
	$Q diff -u <(echo -n) <($(GOIMPORTS) -d -local $(MODULE) $$(find . -type f -name '*.go' -not -path "./vendor/*"))

.PHONY: check
check: check-fmt lint test-race ## Run all checks

.PHONY: generate
generate: | $(GO_ENUM) # Generate code
	$Q $(GO) generate ./...
	$Q $(MAKE) fmt

# Misc

.PHONY: clean
clean: ; $(info $(M) cleaning…)	@ ## Cleanup everything
	$Q rm -rf $(BIN)

.PHONY: help
help:
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: version
version:
	@echo $(VERSION)
