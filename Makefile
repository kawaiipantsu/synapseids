# SynapseIDS — build automation. See PROJECT.md for the target contract and
# CLAUDE.md for the development loop.

MODULE   := github.com/kawaiipantsu/synapseids
PKG      := $(MODULE)/internal/version
BINARIES := synapsed synapse synapse-sensor

VERSION ?= $(shell sed -n 's/^## \[\([0-9][^]]*\)\].*/\1/p' CHANGELOG.md 2>/dev/null | head -1)
VERSION := $(if $(VERSION),$(VERSION),0.1.0-dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DIRTY   := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo true || echo false)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X '$(PKG).Version=$(VERSION)' \
	-X '$(PKG).Commit=$(COMMIT)' \
	-X '$(PKG).Dirty=$(DIRTY)'
ifndef SOURCE_DATE_EPOCH
LDFLAGS += -X '$(PKG).Date=$(DATE)'
endif

GO    ?= go
DIST  := dist
COVER := coverage.out

# Linux release matrix: intel + arm, 32 + 64 bit. Non-negotiable (PROJECT.md
# §27, §28.16) — do not change this line.
LINUX_ARCHES := amd64 386 arm64 arm

# FreeBSD matrix, added for the OPNsense sensor (ADR 0014). An OPNsense
# firewall is a FreeBSD host: amd64 covers appliances and VMs, arm64 covers
# Netgate / PC Engines-class hardware. Only synapse-sensor *must* build here;
# synapsed and synapse happen to cross-compile cleanly too, so they ride along
# in the tarball. This matrix is additive — the four Linux targets above are
# built by exactly the same rules they always were.
FREEBSD_ARCHES   := amd64 arm64
FREEBSD_BINARIES := synapse-sensor synapsed synapse

# The pkg(8) ABI the OPNsense plugin package is built for. OPNsense 24.x and
# 25.x are FreeBSD 14. Override for a future base: `make opnsense-pkg
# FREEBSD_VERSION=15`, or set ABIS to a full explicit list.
FREEBSD_VERSION ?= 14
OPNSENSE_ABIS   ?= $(foreach a,$(FREEBSD_ARCHES),FreeBSD:$(FREEBSD_VERSION):$(a))

.DEFAULT_GOAL := help

## ---------------------------------------------------------------- help

.PHONY: help
help: ## Show available targets
	@echo "Development:"
	@echo "  run                Run synapsed (ARGS=... to pass arguments)"
	@echo "  deps               Download and verify modules"
	@echo "  fmt / fmt-check    Format code / fail if unformatted"
	@echo "  vet / lint         go vet / golangci-lint when installed"
	@echo "  test / race        Run the test suite / with the race detector"
	@echo "  bench / coverage   Benchmarks / HTML coverage report"
	@echo "  generate           Regenerate PCAP fixtures (testdata/gen)"
	@echo ""
	@echo "Web UI (Node; never invoked by the Go build):"
	@echo "  web                Build the React SPA into web/dist (commit the result)"
	@echo "  web-dev            Vite dev server with /api proxy to :8080"
	@echo "  web-check          Type-check the SPA (tsc --noEmit)"
	@echo ""
	@echo "Build:"
	@echo "  build              Build all three host binaries"
	@echo "  build-linux        Build every binary for all four Linux arches"
	@echo "  build-freebsd      Build the sensor for FreeBSD amd64 + arm64 (OPNsense)"
	@echo "  build-all          Linux + FreeBSD"
	@echo "  install            go install all three into GOPATH/bin"
	@echo "  clean              Remove generated files"
	@echo ""
	@echo "Release:"
	@echo "  man                Gzip the man pages into dist/"
	@echo "  dist               tar.gz per arch + OPNsense .pkg + SHA256SUMS"
	@echo "  deb                Four .deb packages (amd64, i386, arm64, armhf)"
	@echo "  opnsense-pkg       OPNsense plugin package (.pkg) per FreeBSD ABI"
	@echo "  snapshot           dist + deb with a snapshot version"
	@echo "  release-check      Verify the tree is ready to tag"
	@echo "  security           govulncheck when installed"
	@echo ""
	@echo "Version: $(VERSION)  Commit: $(COMMIT)"

## ---------------------------------------------------------------- dev

.PHONY: deps
deps: ## Download and verify modules
	$(GO) mod download
	$(GO) mod verify

.PHONY: fmt
fmt: ## Format code
	$(GO) fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail when code is not gofmt-clean
	@unformatted=$$(gofmt -l . 2>/dev/null || true); \
	if [ -n "$$unformatted" ]; then echo "not gofmt'd:"; echo "$$unformatted"; exit 1; fi

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: lint
lint: ## Run golangci-lint when installed, else go vet
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed; running go vet"; $(GO) vet ./...; \
	fi

.PHONY: test
test: ## Run the full test suite
	$(GO) test ./...

.PHONY: race
race: ## Run tests with the race detector
	$(GO) test -race ./...

.PHONY: bench
bench: ## Run benchmarks
	$(GO) test -run '^$$' -bench=. -benchmem ./...

.PHONY: coverage
coverage: ## Generate an HTML coverage report
	$(GO) test -coverprofile=$(COVER) -covermode=atomic ./...
	$(GO) tool cover -func=$(COVER) | tail -1
	$(GO) tool cover -html=$(COVER) -o coverage.html
	@echo "wrote coverage.html"

.PHONY: generate
generate: ## Regenerate the committed PCAP fixtures
	$(GO) run ./testdata/gen

.PHONY: run
run: ## Run synapsed (ARGS=... to pass arguments)
	$(GO) run -ldflags "$(LDFLAGS)" ./cmd/synapsed $(ARGS)

## ---------------------------------------------------------------- web ui

WEB_UI := web/ui

# The Go build never runs any of these: web/dist/ is committed and embedded by
# web/web.go (//go:embed all:dist). Run `make web` and commit web/dist/ after
# touching anything under web/ui/. Requires Node 18 + npm (see web/ui/package.json).
.PHONY: web
web: ## Build the React SPA into web/dist (run + commit after editing web/ui/)
	cd $(WEB_UI) && npm ci && npm run build

.PHONY: web-dev
web-dev: ## Vite dev server, proxying /api + /api/v1/stream to 127.0.0.1:8080
	cd $(WEB_UI) && { [ -d node_modules ] || npm ci; } && npm run dev

.PHONY: web-check
web-check: ## Type-check the SPA (tsc --noEmit)
	cd $(WEB_UI) && { [ -d node_modules ] || npm ci; } && npm run typecheck

## ---------------------------------------------------------------- build

.PHONY: build
build: ## Build all three host binaries
	@for b in $(BINARIES); do \
		echo "building $$b"; \
		CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $$b ./cmd/$$b || exit 1; \
	done

# $(1) = GOARCH
define build_linux_arch
	@echo "building linux/$(1)"
	@mkdir -p $(DIST)/synapseids_$(VERSION)_linux_$(1)
	@for b in $(BINARIES); do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$(1) $(if $(filter arm,$(1)),GOARM=7,) \
			$(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(DIST)/synapseids_$(VERSION)_linux_$(1)/$$b ./cmd/$$b || exit 1; \
	done

endef

.PHONY: build-linux
build-linux: ## Build every binary for all four Linux arches
	$(foreach a,$(LINUX_ARCHES),$(call build_linux_arch,$(a)))

# $(1) = GOARCH
define build_freebsd_arch
	@echo "building freebsd/$(1)"
	@mkdir -p $(DIST)/synapseids_$(VERSION)_freebsd_$(1)
	@for b in $(FREEBSD_BINARIES); do \
		CGO_ENABLED=0 GOOS=freebsd GOARCH=$(1) \
			$(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(DIST)/synapseids_$(VERSION)_freebsd_$(1)/$$b ./cmd/$$b || exit 1; \
	done

endef

.PHONY: build-freebsd
build-freebsd: ## Build the sensor (and friends) for FreeBSD amd64 + arm64
	$(foreach a,$(FREEBSD_ARCHES),$(call build_freebsd_arch,$(a)))

.PHONY: build-all
build-all: build-linux build-freebsd ## Every release target: 4 Linux arches + 2 FreeBSD arches

.PHONY: install
install: ## go install all three into GOPATH/bin
	@for b in $(BINARIES); do \
		CGO_ENABLED=0 $(GO) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/$$b || exit 1; \
	done

.PHONY: clean
clean: ## Remove generated files (keeps the committed web/dist/ bundle)
	rm -rf $(DIST) $(BINARIES) $(COVER) coverage.html
	rm -rf $(WEB_UI)/node_modules $(WEB_UI)/.vite $(WEB_UI)/*.tsbuildinfo
	$(GO) clean -cache -testcache >/dev/null 2>&1 || true

.PHONY: security
security: ## Run govulncheck when installed
	@if command -v govulncheck >/dev/null 2>&1; then govulncheck ./...; \
	else echo "govulncheck not installed: go install golang.org/x/vuln/cmd/govulncheck@latest"; fi

## ---------------------------------------------------------------- release

.PHONY: man
man: ## Gzip the man pages into dist/
	@mkdir -p $(DIST)
	@for b in $(BINARIES); do \
		gzip -9 -n -c packaging/man/$$b.1 > $(DIST)/$$b.1.gz; \
	done
	@echo "wrote $(DIST)/*.1.gz"

.PHONY: opnsense-pkg
opnsense-pkg: build-freebsd ## Build the OPNsense plugin package (.pkg) per FreeBSD ABI
	@VERSION=$(VERSION) DIST=$(DIST) ABIS="$(OPNSENSE_ABIS)" scripts/package-opnsense.sh

.PHONY: dist
dist: build-linux build-freebsd man ## tar.gz per arch + OPNsense .pkg + SHA256SUMS
	@VERSION=$(VERSION) DIST=$(DIST) BINARIES="$(BINARIES)" scripts/package.sh
	@VERSION=$(VERSION) DIST=$(DIST) ABIS="$(OPNSENSE_ABIS)" \
		FREEBSD_ARCHES="$(FREEBSD_ARCHES)" FREEBSD_BINARIES="$(FREEBSD_BINARIES)" \
		scripts/package-opnsense.sh

.PHONY: deb
deb: build-linux man ## Four .deb packages (amd64, i386, arm64, armhf)
	@VERSION=$(VERSION) DIST=$(DIST) BINARIES="$(BINARIES)" scripts/package-deb.sh

.PHONY: snapshot
snapshot: ## dist + deb with a snapshot version
	@$(MAKE) --no-print-directory dist deb VERSION=$(VERSION)-snapshot.$(COMMIT)

.PHONY: release-check
release-check: fmt-check vet lint test build-linux ## Verify the tree is ready to tag
	@VERSION=$(VERSION) scripts/release-check.sh
