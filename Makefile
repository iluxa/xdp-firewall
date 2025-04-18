GO := go
BPF2GO := github.com/cilium/ebpf/cmd/bpf2go
TARGET := xdpfw
GRPC_CLIENT := xdpfw-cli
SRC_DIR := internal/bpf
BPF_SRC := $(SRC_DIR)/bpf.c
PROTO_DIR = pkg/proto
PROTO_FILES = $(PROTO_DIR)/firewall.proto
GENERATED_DIR = internal/gen

# Default target
all: generate build

generate:
	go generate ./internal/bpf/...

build: generate proto
	CGO_ENABLED=0 $(GO) build -ldflags "-extldflags -static -s -w" -o $(TARGET) ./cmd
	CGO_ENABLED=0 $(GO) build -ldflags "-extldflags -static -s -w" -o $(GRPC_CLIENT) ./cmd/grpc_client

# Clean generated files and build artifacts
clean:
	rm -f $(TARGET)
	rm -f $(SRC_DIR)/xdpProg_bpfel.go $(SRC_DIR)/xdpProg_bpfeb.go

.PHONY: all generate build clean proto

proto:
	buf generate --template buf.gen.yaml $(PROTO_FILES)

test:
	sudo $(GO) test ./...