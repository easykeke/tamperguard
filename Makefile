GO      ?= go
BIN     ?= bin
VERSION ?= 0.1.0
LDFLAGS := -s -w

.PHONY: all build clean test vet fmt bpf e2e tools

all: build

## build: compile the three binaries into bin/
build:
	@mkdir -p $(BIN)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/ ./cmd/tg-server ./cmd/tg-agent ./cmd/tg-publish
	@ls -l $(BIN)

## bpf: regenerate the CO-RE Go bindings (needs clang, llvm-strip, bpftool)
bpf:
	cd internal/enforcer && $(GO) run github.com/cilium/ebpf/cmd/bpf2go -cc clang \
		-go-package enforcer \
		-cflags "-O2 -g -Wall -Wno-unused-function -I../../bpf" \
		-target bpfel tg ../../bpf/tg_protect.bpf.c

## vmlinux: regenerate bpf/vmlinux.h from the running kernel's BTF
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
	@wc -l bpf/vmlinux.h

## test: unit tests (the eBPF integration test needs root and skips otherwise)
test:
	$(GO) test ./...

## e2e: full pipeline smoke test (Linux, run as root)
e2e:
	bash test/e2e/e2e-sim.sh

## vet: static checks
vet:
	$(GO) vet ./...

## fmt: format all Go sources
fmt:
	gofmt -l -w .

## clean: remove build output
clean:
	rm -rf $(BIN)
