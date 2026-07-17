# BlakBox bundle-format library + CLI.
#
# The appliance ships in FIPS mode: the on-box verify path (ECDSA P-384 +
# SHA-384) MUST be built against the FIPS 140-3 validated Go module
# (GOFIPS140=v1.0.0, CMVP #5247). These targets make the FIPS build the
# reproducible, shippable artifact rather than an operator convention — a plain
# `go build` links non-validated crypto and would silently break the FIPS claim.
#
# The appliance is aarch64 (Dell GB10 / DGX OS 7); the release build host is
# x86-64. Both get FIPS-built binaries. `bundle version` on the output reports
# `fips140: v1.0.0` so factory imaging and release provenance can assert on it.

GOFIPS140 ?= v1.0.0
DIST      ?= dist

.PHONY: all build test test-fips test-strict appliance host dist clean

all: build test

build:
	go build ./...

test:
	go test ./...

# Full FIPS 140-3 module test (ML-DSA runs as a non-validated hedge).
test-fips:
	GOFIPS140=$(GOFIPS140) go test ./...

# Strict approved-path-only test (the phase-1 trust path incl. the CLI verify).
test-strict:
	GOFIPS140=$(GOFIPS140) GODEBUG=fips140=only \
	  go test -run '^(TestSignVerify|TestVerifyRejects|TestSignRejects|TestStream|TestKeywrap|TestWrap|TestUnwrap|TestPolicy|TestMode|TestSealOpen|TestCLI)' ./...

# FIPS-built CLI for the aarch64 appliance (/opt/blakbox/bin/bundle).
appliance:
	GOOS=linux GOARCH=arm64 GOFIPS140=$(GOFIPS140) \
	  go build -trimpath -o $(DIST)/bundle-linux-arm64 ./cmd/bundle

# FIPS-built CLI for the x86-64 release/build host.
host:
	GOOS=linux GOARCH=amd64 GOFIPS140=$(GOFIPS140) \
	  go build -trimpath -o $(DIST)/bundle-linux-amd64 ./cmd/bundle

# Both shippable binaries. Verify each reports fips140=$(GOFIPS140):
#   ./$(DIST)/bundle-linux-amd64 version
dist: appliance host

clean:
	rm -rf $(DIST)
