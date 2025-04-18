# xdp-firewall

`xdp-firewall` is a high-performance, eBPF-based firewall built using the XDP (eXpress Data Path) framework. It provides a lightweight and efficient way to filter and manage network traffic directly in the Linux kernel, offering low-latency packet processing.

## Features

- **Performant traffic processing**: Rule lookup is performed in constant time.
- **eBPF-based Filtering**: Leverages eBPF and XDP for high-performance packet filtering.
- **gRPC API**: Provides a gRPC interface for managing firewall rules.
- **CIDR-based Rules**: Supports source and destination IP filtering using CIDR notation.
- **Protocol and Port Filtering**: Allows filtering based on L4 protocols (TCP/UDP) and ports.
- **Priority-based Rules**: Supports rule prioritization for fine-grained control.
- **Lightweight**: Minimal overhead with kernel-level packet processing.

## Limitations

- Supports only IPv4

## Getting Started

1. Start from docker:
```sh
alias xdpfw='docker run --rm --privileged --network=host -it gilyav/xdp-firewall'
xdpfw xdpfw -i lo -m generic
```

2. On another terminal add new rule:
```sh
alias xdpfw='docker run --rm --privileged --network=host -it gilyav/xdp-firewall'
xdpfw xdpfw-cli add
xdpfw xdpfw-cli list
```

3. Use help to add more rules:
```sh
xdpfw xdpfw-cli add -h
```

## Build

### Prerequisites

- Linux kernel with eBPF and XDP support.
- Docker (optional, for containerized builds).
- Go (1.18 or later).
- `clang` and `llvm` for compiling eBPF programs.

see [build Dockerfile](/Dockerfile.build) for deps

### Build

1. Build the Docker image:
   ```sh
   docker build -t xdp-firewall .
   ```

2. Build binaries using make:
   ```sh
   make
   ```

2. Run tests:
   ```sh
   sudo make tests
   ```

## Development

### Architecture

The project consists of the following components:

1. **eBPF Program**: The core packet filtering logic implemented in eBPF and loaded into the kernel using XDP.
2. **Firewall Manager**: A Go-based user-space application that interacts with the eBPF maps to manage rules.
3. **gRPC Server**: Exposes a gRPC API for adding, deleting, and listing firewall rules.
4. **gRPC Client**: A command-line client for interacting with the gRPC server.


#### Directory Structure

- `internal/bpf`: Contains the eBPF program source code.
- `internal/fm`: Implements the firewall manager logic.
- `internal/proto`: gRPC protocol definitions and server implementation.
- `cmd/grpc_client`: Command-line gRPC client.
- `cmd/server`: gRPC server entry point.

# License

This project is licensed under the [GPLv2 License](LICENSE). You are free to use, modify, and distribute this project under the terms of the GPLv2 license.

## Acknowledgments

- [XDP](https://www.iovisor.org/technology/xdp): For the high-performance packet processing framework.
- [gRPC](https://grpc.io/): For enabling efficient communication between the client and server.
- [Linux Kernel](https://www.kernel.org/): For supporting eBPF and XDP technologies.
- [Cilium eBPF](https://github.com/cilium/ebpf): For providing the Go library for working with eBPF programs.