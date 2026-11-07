# cau-kernel build.
#
#   make build          # the default sensor (pure Go, no eBPF, builds anywhere)
#   make test           # go test -race
#   make bpf-object     # compile the BPF-LSM object into the enforce package
#   make enforce        # build WITH eBPF enforcement (needs clang + the object)
#
# The default binary is dependency-free and always builds. The eBPF loader is
# behind the `ebpf` build tag and embeds the compiled object, so enforcement is
# opt-in and only its build needs clang + cilium/ebpf.

GO      ?= go
CLANG   ?= clang
BINARY  ?= cau-kernel
EBPF_OBJ := internal/enforce/lsm_guard.bpf.o
NET_OBJ  := internal/enforce/lsm_netshell.bpf.o

.PHONY: build test vet fmt-check bpf-object enforce fuzz clean vm-test

FUZZTIME ?= 20s
# Coverage-guided fuzzing of the untrusted-input parsers. Seed corpora also run
# as fast unit tests under `make test`, so this target is for hunting.
fuzz:
	$(GO) test ./internal/kstate/ -run '^$$' -fuzz '^FuzzCollect$$' -fuzztime $(FUZZTIME)
	$(GO) test ./internal/ksign/  -run '^$$' -fuzz '^FuzzOpen$$'    -fuzztime $(FUZZTIME)

build:
	$(GO) build -o $(BINARY) .

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt-check:
	@out="$$(gofmt -l $$(find . -name '*.go'))"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

bpf-object:
	$(MAKE) -C bpf lsm_guard.bpf.o lsm_netshell.bpf.o lsm_fileopen.bpf.o lsm_killguard.bpf.o
	cp bpf/lsm_guard.bpf.o $(EBPF_OBJ)
	cp bpf/lsm_netshell.bpf.o $(NET_OBJ)

# Boot the running kernel in QEMU and exercise the guards end to end: the real
# verifier, real execve, no root on the host. See scripts/vm-test.sh.
vm-test: bpf-object
	scripts/vm-test.sh

# Build with eBPF enforcement compiled in. Requires the object to be present
# (bpf-object) and network access to fetch cilium/ebpf on first build.
enforce: bpf-object
	$(GO) build -tags ebpf -o $(BINARY) .

clean:
	rm -f $(BINARY) $(EBPF_OBJ) $(NET_OBJ)
	$(MAKE) -C bpf clean
