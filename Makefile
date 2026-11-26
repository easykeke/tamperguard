GO      ?= go
BIN     ?= bin
VERSION ?= 0.2.2
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

## e2e: userspace pipeline smoke test (Linux, run as root)
e2e: e2e-sim

## e2e-sim: full pipeline with the observe backend
e2e-sim:
	bash test/e2e/e2e-sim.sh

## e2e-ebpf: real kernel enforcement; needs a kernel with bpf in the LSM list
e2e-ebpf:
	bash test/e2e/e2e-ebpf.sh

## e2e-fanotify: degraded detect-and-restore path; needs CONFIG_FANOTIFY + root
e2e-fanotify:
	bash test/e2e/e2e-fanotify.sh

## e2e-upgrade: signed self-upgrade channel
e2e-upgrade:
	bash test/e2e/e2e-upgrade.sh

## build-windows: cross-compiled Windows binaries (linux/amd64 host)
build-windows:
	bash scripts/build-windows.sh

## rasp-java: build the Java agent jar (needs JDK 17+)
rasp-java:
	bash rasp/java/build.sh

## e2e-rasp: Node.js runtime probe (needs node in PATH)
e2e-rasp:
	bash test/e2e/e2e-rasp.sh

## e2e-rasp-java: JVM runtime probe (needs JDK 17-21)
e2e-rasp-java:
	bash test/e2e/e2e-rasp-java.sh

## e2e-pull: cross-machine (pull) publishing
e2e-pull:
	bash test/e2e/e2e-pull.sh

## e2e-landlock: process self-protection (Landlock)
e2e-landlock:
	bash test/e2e/e2e-landlock.sh

## e2e-proxy-signed: proxy with the control-plane signed manifest
e2e-proxy-signed:
	bash test/e2e/e2e-proxy-signed.sh

## e2e-uninstall: agent uninstall challenge/approval flow
e2e-uninstall:
	bash test/e2e/e2e-uninstall.sh

## e2e-proxy: web-layer integrity proxy
e2e-proxy:
	bash test/e2e/e2e-proxy.sh

## e2e-verity: fs-verity release hardening (skips on kernels without support)
e2e-verity:
	bash test/e2e/e2e-verity.sh

## e2e-all: every end-to-end test (run as root; needs node/jdk/clang for some)
e2e-all: e2e-sim e2e-ebpf e2e-fanotify e2e-upgrade e2e-rasp e2e-rasp-java e2e-pull e2e-landlock e2e-verity e2e-proxy

## release: build linux amd64/arm64 tarballs with checksums into dist/release
release:
	VERSION=$(VERSION) bash scripts/release.sh

## vet: static checks
vet:
	$(GO) vet ./...

## fmt: format all Go sources
fmt:
	gofmt -l -w .

## clean: remove build output
clean:
	rm -rf $(BIN)
