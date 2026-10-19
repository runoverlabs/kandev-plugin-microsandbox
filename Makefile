.PHONY: build test test-race test-ui fmt vet lint validate-manifest \
	security security-secrets security-deps claude-md \
	package package-host verify-package verify-package-host clean

# VERSION is read from manifest.yaml so the packaged asset name cannot drift
# from the version the release workflow gates the tag against.
ID := kandev-plugin-microsandbox
BIN := bin/$(ID)
VERSION := $(shell sed -n 's/^version: *"\(.*\)"/\1/p' manifest.yaml | head -1)
STAGE := .build/stage
PKG_OUT := $(ID)-$(VERSION).tar.gz

# The sibling kandev checkout the `replace` in go.mod points at. plugin-pack
# and the manifest check run from INSIDE it, so they resolve against kandev's
# own go.sum rather than this module's.
KANDEV_SDK := ../kandev/apps/backend

# Release binaries are stripped and path-trimmed: `-s -w` drops the symbol
# table and DWARF (Go keeps pclntab, so panics still carry file and line), and
# `-trimpath` keeps the build machine's paths out of the artifact.
RELEASE_FLAGS := -trimpath -ldflags="-s -w"

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

## Recreate the local-only CLAUDE.md pointer to AGENTS.md. Never overwrites.
claude-md:
	@if [ -f CLAUDE.md ]; then \
		echo "CLAUDE.md already present; leaving it alone"; \
	else \
		printf '%s\n' \
			'# CLAUDE.md' \
			'' \
			'**Read [AGENTS.md](AGENTS.md) — it is the guide for this repo.**' \
			'' \
			'This file is gitignored and local-only; AGENTS.md is the single source of' \
			'truth. Do not move content here, and do not commit it.' > CLAUDE.md; \
		echo "wrote CLAUDE.md"; \
	fi

## Host-platform binary, for development only. Kandev installs packages.
build:
	mkdir -p bin
	go build -o $(BIN) ./server

test:
	go test ./... -count=1

test-race:
	go test -race ./... -count=1

## Builds the bundle first, then runs the UI's unit tests.
test-ui:
	npm test

ui/bundle.js: $(wildcard ui/src/*.ts) package.json ui/tsconfig.json
	npm run build:ui

fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed: $$out"; exit 1; fi

vet:
	go vet ./...

lint: fmt vet validate-manifest

## Validate manifest.yaml with the pinned Kandev's own manifest package. It is
## internal to the Kandev module, so the checker is compiled inside that module
## through an overlay; nothing is written into the sibling checkout.
validate-manifest:
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
		sdk="$$(cd $(KANDEV_SDK) && pwd)"; \
		printf '{"Replace":{"%s/cmd/msb-manifestcheck/main.go":"%s/scripts/_manifestcheck/main.go"}}' \
			"$$sdk" "$(CURDIR)" > "$$tmp/overlay.json"; \
		cd "$$sdk" && go run -overlay "$$tmp/overlay.json" ./cmd/msb-manifestcheck "$(CURDIR)/manifest.yaml"

# Pinned so a local run and CI check the same thing. Bump both here and in
# .github/workflows/security.yml.
GITLEAKS_VERSION := 8.30.0
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0

security: security-secrets security-deps

## Secret detection over the working tree and the history. Needs gitleaks on
## PATH: `go install github.com/gitleaks/gitleaks/v8@v$(GITLEAKS_VERSION)`.
security-secrets:
	@command -v gitleaks >/dev/null || { \
		echo "gitleaks not found: install v$(GITLEAKS_VERSION) or run the Security workflow"; exit 1; }
	gitleaks git . --no-banner --redact --verbose
	gitleaks dir . --no-banner --redact --verbose

security-deps:
	go run $(GOVULNCHECK) ./...

# The package carries the built bundle and its stylesheet, not the UI's
# sources or tests.
define stage
	rm -rf $(STAGE)
	mkdir -p $(STAGE)/server $(STAGE)/ui
	cp manifest.yaml $(STAGE)/manifest.yaml
	cp ui/bundle.js ui/plugin.css $(STAGE)/ui/
endef

## Every platform in manifest.yaml's runtime.executables, packed for release.
package: validate-manifest ui/bundle.js
	$(stage)
	@for platform in $(PLATFORMS); do \
		os="$${platform%/*}"; arch="$${platform#*/}"; ext=""; \
		[ "$$os" = windows ] && ext=".exe"; \
		echo "build $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build $(RELEASE_FLAGS) -o $(STAGE)/server/plugin-$$os-$$arch$$ext ./server || exit 1; \
	done
	cd $(KANDEV_SDK) && go run ./cmd/plugin-pack -dir $(CURDIR)/$(STAGE) -out $(CURDIR)/$(PKG_OUT)
	rm -rf $(STAGE)
	@echo "Wrote $(PKG_OUT)"

## Host-platform-only package, for local iteration.
package-host: validate-manifest ui/bundle.js
	$(stage)
	go build $(RELEASE_FLAGS) -o $(STAGE)/server/plugin-$$(go env GOOS)-$$(go env GOARCH)$$(go env GOEXE) ./server
	cd $(KANDEV_SDK) && go run ./cmd/plugin-pack -dir $(CURDIR)/$(STAGE) -out $(CURDIR)/$(PKG_OUT) -platform-only
	rm -rf $(STAGE)
	@echo "Wrote $(PKG_OUT)"

## Build and check the all-platform archive.
verify-package: package
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
		tar -xzf "$(PKG_OUT)" -C "$$tmp"; \
		test -f "$$tmp/manifest.yaml"; \
		test -f "$$tmp/checksums.txt"; \
		test -f "$$tmp/ui/bundle.js"; \
		test -f "$$tmp/ui/plugin.css"; \
		test ! -e "$$tmp/ui/src"; \
		for platform in $(PLATFORMS); do \
			os="$${platform%/*}"; arch="$${platform#*/}"; ext=""; \
			[ "$$os" = windows ] && ext=".exe"; \
			test -f "$$tmp/server/plugin-$$os-$$arch$$ext" || { echo "missing $$os/$$arch"; exit 1; }; \
		done; \
		test ! -e "$$tmp/internal"; \
		test ! -e "$$tmp/go.mod"; \
		(cd "$$tmp" && sha256sum -c checksums.txt)
	@echo "verify-package OK"

verify-package-host: package-host
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
		tar -xzf "$(PKG_OUT)" -C "$$tmp"; \
		test -f "$$tmp/manifest.yaml"; \
		test -f "$$tmp/checksums.txt"; \
		test -f "$$tmp/server/plugin-$$(go env GOOS)-$$(go env GOARCH)$$(go env GOEXE)"; \
		test -f "$$tmp/ui/bundle.js"; \
		(cd "$$tmp" && sha256sum -c checksums.txt)
	@echo "verify-package-host OK"

clean:
	rm -rf bin .build $(ID)-*.tar.gz node_modules
