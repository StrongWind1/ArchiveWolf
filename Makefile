.PHONY: fmt fmt-fix lint lint-fix doc dev build check \
        test test-zip-crypto test-rar-13 \
        audit machete \
        editorconfig yamllint actionlint taplo markdownlint hygiene \
        build-linux-musl \
        build-linux-arm-musl \
        build-macos-arm build-macos-x86 build-macos-universal \
        build-windows \
        dist size \
        fix hooks clean check-all all

# Default target -- running bare `make` builds dist artifacts for the current platform.
.PHONY: all
all: dist

CARGO   := cargo
NEXTEST := cargo nextest run
DIST    := dist
BIN     := archivewolf

# -- OS / architecture detection -----------------------------------------------
UNAME_S := $(shell uname -s 2>/dev/null)
UNAME_M := $(shell uname -m 2>/dev/null)

ifeq ($(findstring Linux,$(UNAME_S)),Linux)
  PLATFORM := linux
else ifeq ($(findstring Darwin,$(UNAME_S)),Darwin)
  PLATFORM := macos
else
  PLATFORM := windows
endif

ifneq (,$(filter arm64 aarch64,$(UNAME_M)))
  ARCH := arm64
else
  ARCH := x86_64
endif

# -- Rust target triples --------------------------------------------------------
TARGET_LINUX_X86_MUSL := x86_64-unknown-linux-musl
TARGET_LINUX_ARM_MUSL := aarch64-unknown-linux-musl
TARGET_MACOS_ARM      := aarch64-apple-darwin
TARGET_MACOS_X86      := x86_64-apple-darwin
TARGET_WIN_X86_MSVC   := x86_64-pc-windows-msvc
TARGET_WIN_X86_GNU    := x86_64-pc-windows-gnu
TARGET_WIN_ARM_MSVC   := aarch64-pc-windows-msvc

# -- Formatting ---------------------------------------------------------------

fmt:
	$(CARGO) fmt --all -- --check

fmt-fix:
	$(CARGO) fmt --all

# -- Linting ------------------------------------------------------------------

lint:
	$(CARGO) clippy --workspace --all-targets --all-features -- --deny warnings

lint-fix:
	$(CARGO) clippy --fix --allow-dirty --workspace --all-targets --all-features

# -- Documentation ------------------------------------------------------------

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --all-features --no-deps

# -- Build ---------------------------------------------------------------------

dev:
	$(CARGO) build --all-features

build:
	$(CARGO) build --profile release --all-features

.PHONY: release
release: build

check:
	$(CARGO) check --workspace --all-targets --all-features

# -- Tests ---------------------------------------------------------------------

# The default test run, of the tool and of the crate that holds the key search of
# `attack zip-crypto` (crates/zip-crypto). One configuration is tested: neither crate has a
# [features] table, so there is no test matrix.
#
# The tests hold the README to the tool: its examples and its names. The guides of the tool are
# kept outside the repository, and are held the same way when their folder is named:
#   ARCHIVEWOLF_GUIDES         path of the folder of the guides
.PHONY: test
test:
	$(NEXTEST) --workspace --all-targets --all-features

# The long searches of `attack zip-crypto`: the header paths from the headers alone, a
# signature, a run of eight with a class behind it, and the whole matrices of the packers and
# of the seed searches. Each takes every thread of the machine, so they run one at a time.
test-zip-crypto:
	@echo "==> attack zip-crypto: the long searches (release mode, ~10 minutes)"
	$(NEXTEST) --release --workspace --all-features -E 'binary(zip_crypto_long_test) | test(/attack::zip_crypto::/)' --run-ignored only

# CI runs this target with its own NEXTEST (.github/workflows/ci.yml, the rar-13 leg of the tests).
test-rar-13:
	@echo "==> RAR 1.3 key recovery on compressed entries (release mode, ~6 minutes)"
	$(NEXTEST) --release --all-features -E 'test(/rar_13_.*key_recovered/)' --run-ignored only

# -- Proofs of the hash lines -----------------------------------------------------
#
# The expected lines under tests/golden/ are held by tests/golden_lines_test.rs in every test
# run. The two targets here need something from outside the repository and fail without it.
# They use plain `cargo test`: nextest ends an integration test after two minutes, which a
# hashcat that still has to build its kernels does not keep to.

# The extractors of the hashcat fork write the lines ArchiveWolf writes, for every fixture.
#   ARCHIVEWOLF_HASHCAT_REPO   path of the hashcat fork, which is only read (git show)
#   ARCHIVEWOLF_PYTHON         the interpreter of the extractors, with its arguments if it
#                              needs any (default: python3)
.PHONY: test-extractors
test-extractors: export ARCHIVEWOLF_PYTHON ?= python3
test-extractors:
	@echo "==> ArchiveWolf against the extractors of the hashcat fork, every fixture"
	$(CARGO) test --all-features --test extractor_identity_test -- --ignored --nocapture --test-threads=1

# The modes of the hashcat fork crack the recorded lines with the passwords of their fixtures.
#   ARCHIVEWOLF_HASHCAT        path of a hashcat binary built from a branch of the fork
.PHONY: test-hashcat
test-hashcat:
	@echo "==> hashcat on the recorded lines, each with its password in a list of three words"
	$(CARGO) test --all-features --test hashcat_crack_test -- --ignored --nocapture --test-threads=1

# -- Dependency auditing --------------------------------------------------------

audit:
	$(CARGO) deny check

machete:
	$(CARGO) machete

# -- File hygiene --------------------------------------------------------------

editorconfig:
	ec

yamllint:
	yamllint --strict -c .yamllint.yml .

actionlint:
	actionlint .github/workflows/*.yml

taplo:
	taplo fmt --check Cargo.toml
	taplo lint Cargo.toml

markdownlint:
	markdownlint-cli2

.PHONY: hygiene
hygiene: editorconfig yamllint actionlint taplo markdownlint

# -- Platform-specific build targets -------------------------------------------

build-linux-musl:
	@if ! command -v musl-gcc > /dev/null 2>&1; then \
		echo "WARNING: musl-gcc not found  --  skipping $(TARGET_LINUX_X86_MUSL)."; \
		echo "  Install: apt install musl-tools && rustup target add $(TARGET_LINUX_X86_MUSL)"; \
	else \
		rustup target add $(TARGET_LINUX_X86_MUSL) 2>/dev/null || true; \
		$(CARGO) build --profile release --no-default-features --target $(TARGET_LINUX_X86_MUSL); \
	fi

build-linux-arm-musl:
	@if ! command -v musl-gcc > /dev/null 2>&1; then \
		echo "WARNING: musl-gcc not found  --  skipping $(TARGET_LINUX_ARM_MUSL)."; \
		echo "  Install: apt install musl-tools && rustup target add $(TARGET_LINUX_ARM_MUSL)"; \
	else \
		rustup target add $(TARGET_LINUX_ARM_MUSL) 2>/dev/null || true; \
		$(CARGO) build --profile release --no-default-features --target $(TARGET_LINUX_ARM_MUSL); \
	fi

build-macos-arm:
	rustup target add $(TARGET_MACOS_ARM) 2>/dev/null || true
	$(CARGO) build --profile release --no-default-features --target $(TARGET_MACOS_ARM)

build-macos-x86:
	rustup target add $(TARGET_MACOS_X86) 2>/dev/null || true
	$(CARGO) build --profile release --no-default-features --target $(TARGET_MACOS_X86)

build-macos-universal:
	@if ! command -v lipo > /dev/null 2>&1; then \
		echo "WARNING: lipo not found  --  skipping universal binary (macOS only)."; \
	elif [ ! -f target/$(TARGET_MACOS_ARM)/release/$(BIN) ] \
	  || [ ! -f target/$(TARGET_MACOS_X86)/release/$(BIN) ]; then \
		echo "WARNING: one or both macOS binaries missing  --  run build-macos-arm and build-macos-x86 first."; \
	else \
		mkdir -p $(DIST); \
		lipo -create \
			-output $(DIST)/$(BIN)-macos-universal \
			target/$(TARGET_MACOS_ARM)/release/$(BIN) \
			target/$(TARGET_MACOS_X86)/release/$(BIN); \
		lipo -info $(DIST)/$(BIN)-macos-universal; \
	fi

build-windows:
	@echo "Windows builds require native CI runners:"
	@echo "  windows-x86_64-msvc.exe   --  windows-latest    (MSVC)"
	@echo "  windows-x86_64-gnu.exe    --  ubuntu-latest     (MinGW)"
	@echo "  windows-arm64-msvc.exe    --  windows-11-arm    (MSVC)"
	@echo "Trigger: git tag vX.Y.Z && git push --tags"

# -- Distribution --------------------------------------------------------------

ifeq ($(PLATFORM)-$(ARCH),linux-x86_64)
  DIST_DEPS := build-linux-musl
else ifeq ($(PLATFORM)-$(ARCH),linux-arm64)
  DIST_DEPS := build-linux-arm-musl
else ifeq ($(PLATFORM),macos)
  DIST_DEPS := build-macos-arm build-macos-x86 build-macos-universal
else
  DIST_DEPS := build-windows
endif

.PHONY: dist
dist: $(DIST_DEPS)
	@mkdir -p $(DIST)
	@built=0; \
	if [ -f target/$(TARGET_LINUX_X86_MUSL)/release/$(BIN) ]; then \
		cp target/$(TARGET_LINUX_X86_MUSL)/release/$(BIN) $(DIST)/$(BIN)-linux-x86_64; \
		echo "  $(DIST)/$(BIN)-linux-x86_64  (musl static)"; \
		built=$$((built+1)); \
	fi; \
	if [ -f target/$(TARGET_LINUX_ARM_MUSL)/release/$(BIN) ]; then \
		cp target/$(TARGET_LINUX_ARM_MUSL)/release/$(BIN) $(DIST)/$(BIN)-linux-arm64; \
		echo "  $(DIST)/$(BIN)-linux-arm64  (musl static)"; \
		built=$$((built+1)); \
	fi; \
	if [ -f target/$(TARGET_MACOS_ARM)/release/$(BIN) ]; then \
		cp target/$(TARGET_MACOS_ARM)/release/$(BIN) $(DIST)/$(BIN)-macos-arm64; \
		echo "  $(DIST)/$(BIN)-macos-arm64"; \
		built=$$((built+1)); \
	fi; \
	if [ -f target/$(TARGET_MACOS_X86)/release/$(BIN) ]; then \
		cp target/$(TARGET_MACOS_X86)/release/$(BIN) $(DIST)/$(BIN)-macos-x86_64; \
		echo "  $(DIST)/$(BIN)-macos-x86_64"; \
		built=$$((built+1)); \
	fi; \
	if [ -f $(DIST)/$(BIN)-macos-universal ]; then \
		echo "  $(DIST)/$(BIN)-macos-universal  (lipo)"; \
		built=$$((built+1)); \
	fi; \
	echo "$$built artifact(s) in $(DIST)/  |  Other platforms: git tag vX.Y.Z && git push --tags"

# -- Size reporting -------------------------------------------------------------

size: build
	@echo "Binary sizes:"
	@ls -lh $(DIST)/$(BIN)-linux-x86_64 2>/dev/null \
		| awk '{print "  linux-x86_64 (musl):  " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-linux-arm64 2>/dev/null \
		| awk '{print "  linux-arm64 (musl):   " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-macos-arm64 2>/dev/null \
		| awk '{print "  macos-arm64:          " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-macos-x86_64 2>/dev/null \
		| awk '{print "  macos-x86_64:         " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-macos-universal 2>/dev/null \
		| awk '{print "  macos-universal:      " $$5}' || true

# -- Convenience ---------------------------------------------------------------

.PHONY: fix
fix: fmt-fix lint-fix

hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks installed (.githooks/pre-commit)"

.PHONY: clean
clean:
	$(CARGO) clean
	rm -rf $(DIST)
	rm -f *.rlib

# -- Gates ---------------------------------------------------------------------
#
# The checks that run on one machine, as one target. There is no MSRV check and no feature
# powerset check, here as in CI: rust-toolchain.toml pins the compiler that `rust-version` in
# Cargo.toml names, and the crate has no features. Bring them back when the two versions part or
# a feature is added.

.PHONY: check-all
check-all: fmt lint audit check test doc hygiene machete

# check-all and the key searches of both attacks that are too slow for the default test run.
.PHONY: check-all-full
check-all-full: check-all test-rar-13 test-zip-crypto


# --- Release: bump version, refresh deps, verify, signed commit + signed tag, push ---
.PHONY: cut-release
cut-release:
	@test -n "$(VERSION)" || { echo "usage: make cut-release VERSION=X.Y.Z"; exit 1; }
	@command -v cargo-set-version > /dev/null 2>&1 || cargo install cargo-edit --locked
	cargo set-version "$(VERSION)"
	cargo upgrade --incompatible
	cargo update
	$(MAKE) check-all
	git add Cargo.toml Cargo.lock
	@git diff --cached --quiet || git commit -S -m "chore(release): v$(VERSION)"
	git tag -s "v$(VERSION)" -m "v$(VERSION)"
	git push origin HEAD
	git push origin "v$(VERSION)"
