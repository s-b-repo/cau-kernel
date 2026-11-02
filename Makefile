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

.PHONY: build test vet fmt-check bpf-object enforce clean

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
	$(MAKE) -C bpf lsm_guard.bpf.o
	cp bpf/lsm_guard.bpf.o $(EBPF_OBJ)

# Build with eBPF enforcement compiled in. Requires the object to be present
# (bpf-object) and network access to fetch cilium/ebpf on first build.
enforce: bpf-object
	$(GO) build -tags ebpf -o $(BINARY) .

clean:
	rm -f $(BINARY) $(EBPF_OBJ)
	$(MAKE) -C bpf clean
