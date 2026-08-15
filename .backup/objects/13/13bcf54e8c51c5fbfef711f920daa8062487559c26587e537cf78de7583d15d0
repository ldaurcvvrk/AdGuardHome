# Keep the Makefile POSIX-compliant.  We currently allow hyphens in target
# names, but that may change in the future.
#
# See https://pubs.opengroup.org/onlinepubs/9799919799/utilities/make.html.
.POSIX:

# This comment is used to simplify checking local copies of the Makefile.  Bump
# this number every time a significant change is made to this Makefile.
#
# AdGuard-Project-Version: 12

# Don't name these macros "GO" etc., because GNU Make apparently makes them
# exported environment variables with the literal value of "${GO:-go}" and so
# on, which is not what we need.  Use a dot in the name to make sure that users
# don't have an environment variable with the same name.
#
# See https://unix.stackexchange.com/q/646255/105635.
GO.MACRO = $${GO:-go}
VERBOSE.MACRO = $${VERBOSE:-0}

# =============================================================================
# Build Targets: ONLY modern Linux platforms
#   - linux/amd64  (Intel/AMD 64-bit servers, VPS, NAS, x86 routers, Docker)
#   - linux/arm64  (ARM64 cloud, Raspberry Pi 4/5, ARM NAS, Android ARM64)
# =============================================================================
GOOS = linux
GOARCHS = amd64 arm64
GOAMD64 = v1
GOARM64 = v8.0

CHANNEL = development
CLIENT_DIR = client_v2
DEPLOY_SCRIPT_PATH = not/a/real/path
DIST_DIR = dist
GOPROXY = https://proxy.golang.org|direct
GOTELEMETRY = off
GOTOOLCHAIN = go1.26.6
GPG_KEY = devteam@adguard.com
GPG_KEY_PASSPHRASE = not-a-real-password
NPM = npm
NPM_FLAGS = --prefix $(CLIENT_DIR)
NPM_INSTALL_FLAGS = $(NPM_FLAGS) --quiet --no-progress
RACE = 0
REVISION = $${REVISION:-$$(git rev-parse --short HEAD)}
SIGN = 1
SIGNER_API_KEY = not-a-real-key
VERSION = v0.0.0

NEXTAPI = 0

# Macros for the build-release target.  If FRONTEND_PREBUILT is 0, the default,
# the macro $(BUILD_RELEASE_DEPS_$(FRONTEND_PREBUILT)) expands into
# BUILD_RELEASE_DEPS_0, and so both frontend and backend dependencies are
# fetched and the frontend is built.  Otherwise, if FRONTEND_PREBUILT is 1, only
# backend dependencies are fetched and the frontend isn't rebuilt.
FRONTEND_PREBUILT = 0
BUILD_RELEASE_DEPS_0 = deps js-build
BUILD_RELEASE_DEPS_1 = go-deps

ENV = env \
	CHANNEL='$(CHANNEL)' \
	DEPLOY_SCRIPT_PATH='$(DEPLOY_SCRIPT_PATH)' \
	DIST_DIR='$(DIST_DIR)' \
	GO="$(GO.MACRO)" \
	GOAMD64='$(GOAMD64)' \
	GOARM64='$(GOARM64)' \
	GOPROXY='$(GOPROXY)' \
	GOTELEMETRY='$(GOTELEMETRY)' \
	GOTOOLCHAIN='$(GOTOOLCHAIN)' \
	GPG_KEY='$(GPG_KEY)' \
	GPG_KEY_PASSPHRASE='$(GPG_KEY_PASSPHRASE)' \
	NEXTAPI='$(NEXTAPI)' \
	PATH="$${PWD}/bin:$$("$(GO.MACRO)" env GOPATH)/bin:$${PATH}" \
	RACE='$(RACE)' \
	REVISION="$(REVISION)" \
	SIGN='$(SIGN)' \
	SIGNER_API_KEY='$(SIGNER_API_KEY)' \
	VERBOSE="$(VERBOSE.MACRO)" \
	VERSION="$(VERSION)" \

ENV_MISC = env \
	PATH="$${PWD}/bin:$$("$(GO.MACRO)" env GOPATH)/bin:$${PATH}" \
	VERBOSE="$(VERBOSE.MACRO)" \

# Keep this target first, so that a naked make invocation triggers a full build.
.PHONY: build
build: deps quick-build

.PHONY: init
init: ; git config core.hooksPath ./scripts/hooks

.PHONY: quick-build
quick-build: js-build go-build

.PHONY: deps lint test
deps: js-deps go-deps
lint: js-lint go-lint
test: js-test go-test

# Build for both target architectures
.PHONY: go-build
go-build: go-build-amd64 go-build-arm64

.PHONY: go-build-amd64
go-build-amd64:
	$(ENV) GOOS=$(GOOS) GOARCH=amd64 "$(GO.MACRO)" build -ldflags="-s -w -X main.version=$(VERSION) -X main.revision=$(REVISION) -X main.channel=$(CHANNEL)" -o $(DIST_DIR)/AdGuardHome_linux_amd64 ./...

.PHONY: go-build-arm64
go-build-arm64:
	$(ENV) GOOS=$(GOOS) GOARCH=arm64 "$(GO.MACRO)" build -ldflags="-s -w -X main.version=$(VERSION) -X main.revision=$(REVISION) -X main.channel=$(CHANNEL)" -o $(DIST_DIR)/AdGuardHome_linux_arm64 ./...

.PHONY: build-release
build-release: $(BUILD_RELEASE_DEPS_$(FRONTEND_PREBUILT))
	@echo "Building release for: linux/amd64, linux/arm64"
	$(MAKE) go-build
	@echo "Release binaries in $(DIST_DIR)/"

.PHONY: js-build js-deps js-typecheck js-lint js-test js-test-e2e
js-build:     ; $(NPM) $(NPM_FLAGS) run build-prod
js-deps:      ; $(NPM) $(NPM_INSTALL_FLAGS) ci
js-typecheck: ; $(NPM) $(NPM_FLAGS) run typecheck
js-lint:      ; $(NPM) $(NPM_FLAGS) run lint
js-test:      ; $(NPM) $(NPM_FLAGS) run test
js-test-e2e:  ; $(NPM) $(NPM_FLAGS) run test:e2e

.PHONY: go-bench go-deps go-env go-fuzz go-lint go-test go-upd-tools
go-bench:     ; $(ENV) GOOS=$(GOOS) GOARCH=amd64 "$(SHELL)" ./scripts/make/go-bench.sh 2>/dev/null || $(ENV) GOOS=$(GOOS) GOARCH=amd64 "$(GO.MACRO)" test -bench=. -benchmem ./...
go-deps:      ; $(ENV) "$(GO.MACRO)" mod download
go-env:       ; $(ENV) "$(GO.MACRO)" env
go-fuzz:      ; $(ENV) GOOS=$(GOOS) GOARCH=amd64 "$(SHELL)" ./scripts/make/go-fuzz.sh 2>/dev/null || echo "Fuzz tests require scripts/"
go-lint:      ; $(ENV) GOOS=$(GOOS) GOARCH=amd64 "$(GO.MACRO)" vet ./...
go-test:      ; $(ENV) GOOS=$(GOOS) GOARCH=amd64 RACE='1' "$(GO.MACRO)" test ./...
go-upd-tools: ; $(ENV) "$(SHELL)" ./scripts/make/go-upd-tools.sh 2>/dev/null || echo "Tool updates require scripts/"

.PHONY: go-check
go-check: go-lint go-test

# Only check target architectures: linux/amd64 and linux/arm64
.PHONY: go-os-check
go-os-check:
	$(ENV) GOOS=$(GOOS) GOARCH=amd64 "$(GO.MACRO)" vet ./...
	$(ENV) GOOS=$(GOOS) GOARCH=arm64 "$(GO.MACRO)" vet ./...

.PHONY: txt-lint
txt-lint: ; $(ENV) "$(SHELL)" ./scripts/make/txt-lint.sh 2>/dev/null || echo "txt-lint requires scripts/"

.PHONY: md-lint sh-lint
md-lint: ; $(ENV_MISC) "$(SHELL)" ./scripts/make/md-lint.sh 2>/dev/null || echo "md-lint requires scripts/"
sh-lint: ; $(ENV_MISC) "$(SHELL)" ./scripts/make/sh-lint.sh 2>/dev/null || echo "sh-lint requires scripts/"

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(DIST_DIR)
	$(ENV) "$(GO.MACRO)" clean -cache -modcache -testcache

# Show supported targets
.PHONY: targets
targets:
	@echo "Supported build targets:"
	@echo "  linux/amd64  - Intel/AMD 64-bit (servers, VPS, NAS, routers, Docker)"
	@echo "  linux/arm64  - ARM64 (cloud, RPi 4/5, ARM NAS, Android/Termux)"
	@echo ""
	@echo "Removed targets:"
	@echo "  Windows, macOS, FreeBSD, OpenBSD, NetBSD"
	@echo "  linux/386, linux/arm, linux/mips, linux/mips64, linux/ppc64, linux/riscv64"
