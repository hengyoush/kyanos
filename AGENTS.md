# Kyanos AGENTS.md

> This file provides AI agents with project background, structure, coding conventions, and workflow information.

## Project Overview

**Kyanos** is an eBPF-based network troubleshooting tool for capturing and analyzing network requests (HTTP, Redis, MySQL, etc.), helping to quickly diagnose network-related issues such as slow queries, high traffic, and anomalies.

### Core Features

1. **Traffic Filtering**: Multi-dimensional filtering by process/container, L7 protocol, request/response size, latency, etc.
2. **Traffic Analysis**: Aggregated metrics for rapid issue identification (e.g., finding largest responses when bandwidth is saturated)
3. **Kernel-level Latency Details**: Visual representation of packet journey from NIC to socket buffer
4. **Automatic SSL Decryption**: Automatic HTTPS traffic decryption to plaintext
5. **Zero Dependencies**: Single binary file with command-line interface

### Technology Stack

- **Language**: Go 1.23+
- **Kernel Technology**: eBPF (using cilium/ebpf library)
- **UI**: Charmbracelet ecosystem (Bubble Tea, Bubbles, Lipgloss)
- **CLI**: Cobra + Viper
- **Supported Protocols**: HTTP, Redis, MySQL, Kafka, MongoDB, RocketMQ, DNS

---

## Project Structure

```
kyanos/
├── main.go                 # Entry point, calls cmd.Execute()
├── go.mod                  # Go dependency management
├── Makefile               # Build scripts
├── bpf/                   # eBPF C programs and headers
│   ├── pktlatency.bpf.c   # Main eBPF program
│   ├── openssl_*.bpf.c    # OpenSSL uprobes for various versions
│   ├── gotls.bpf.c        # Go TLS uprobe
│   ├── *.h                # BPF header files
│   └── loader/            # BPF loader (Go)
├── cmd/                   # CLI command definitions
│   ├── root.go            # Root command and global flags
│   ├── watch.go           # watch subcommand
│   ├── stat.go            # stat subcommand
│   └── *.go               # Other protocol commands
├── agent/                 # Core Agent logic
│   ├── agent.go           # Agent startup and main loop
│   ├── conn/              # Connection management, event handling
│   ├── protocol/          # Protocol parsers
│   ├── analysis/          # Traffic analysis
│   ├── render/            # UI rendering
│   └── metadata/          # Container/K8s metadata
├── common/                # Shared utilities and types
│   ├── log.go             # Logging system
│   ├── utils.go           # General utilities
│   └── *.go
├── version/               # Version information
├── vmlinux/               # vmlinux.h for different architectures
├── libbpf/                # libbpf submodule
└── docs/                  # Documentation
```

---

## Build System

### Dependencies

- **Go**: 1.23+
- **Clang**: 10.0+
- **LLVM**: 10.0+
- **Linux Headers**: linux-tools-common, linux-tools-generic
- **Others**: pkgconf, libelf-dev

### Common Build Commands

```bash
# Development build (local testing)
make build-bpf && make

# Full build with BTF (for older kernels)
make build-bpf && make btfgen BUILD_ARCH=x86_64 ARCH_BPF_NAME=x86 && make

# Debug build
make kyanos-debug

# Run tests
make test

# Format code
make format
```

### BPF Code Generation

The project uses `go generate` to generate BPF skeleton code:

```bash
# Defined in bpf/loader/loader.go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ...

TARGET=amd64 go generate ./bpf/  # x86_64
TARGET=arm64 go generate ./bpf/  # arm64
```

---

## Coding Conventions

### Go Style Guidelines

1. **Package Naming**: All lowercase, short and meaningful, avoid underscores
2. **File Naming**: All lowercase, use underscores for separation, e.g., `kern_event_handler.go`
3. **Interface Naming**: Verb + Noun, e.g., `ProtocolStreamParser`
4. **Error Handling**: Explicit handling, use `common.DefaultLog` for logging
5. **Logging**: Use dedicated loggers like `common.AgentLog`, `common.BPFLog`

### Key Patterns

#### Agent Startup Flow

```go
// agent/agent.go: SetupAgent()
1. Check BPF permissions (CAP_BPF)
2. Initialize ConnManager
3. Initialize ProcessorManager
4. Load BPF programs (loader.LoadBPF)
5. Start event pulling goroutines
6. Start rendering UI
```

#### Protocol Parser

```go
// agent/protocol/protocol.go

// Implement ProtocolStreamParser interface
type ProtocolStreamParser interface {
    Match(reqStreams, respStreams) []Record
    FindBoundary(streamBuffer, messageType, startPos) int
    ParseRequest(streamBuffer, messageType) *ParsedMessage
    // ...
}

// Register parser
func init() {
    ParsersMap[bpf.AgentTrafficProtocolTKProtocolXXX] = func() ProtocolStreamParser {
        return &XXXStreamParser{}
    }
}
```

#### eBPF Map Definition

```c
// bpf/pktlatency.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct sock_key));
    __uint(value_size, sizeof(struct conn_id_s_t));
    __uint(max_entries, 65535);
} sock_key_conn_id_map SEC(".maps");
```

---

## Testing

### Test Structure

```
agent/
├── agent_test.go              # Agent tests
├── agent_utils_test.go        # Utility tests
└── protocol/
    └── http_test.go           # Protocol parser tests
```

### Running Tests

```bash
# All tests
go test -v ./...

# Specific package tests
go test -v ./agent/...

# Benchmark tests
go test -bench=. ./...
```

---

## Troubleshooting

### 1. BPF Loading Failed

- Check kernel version (requires 3.10.0-957+ or 4.14+)
- Check if BTF is enabled: `zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz`
- Use `--btf` flag to specify external BTF file

### 2. Container-related Features Not Working

- Ensure access to Docker/Containerd/CRI
- Use `--docker-address`, `--containerd-address` to specify endpoints

### 3. SSL Decryption Failed

- Check if OpenSSL version is supported
- Ensure the process has ptrace permissions

---

## Contributing

### Adding New Protocol Support

1. Add protocol detection logic in `bpf/protocol_inference.h`
2. Create parser in `agent/protocol/` implementing `ProtocolStreamParser`
3. Add corresponding subcommand in `cmd/`
4. Add test cases

### Modifying BPF Code

1. Modify `.c` or `.h` files
2. Run `make build-bpf` to regenerate skeleton code
3. Test and verify

---

## Resources

- **Documentation**: https://kyanos.io/
- **GitHub**: https://github.com/hengyoush/kyanos
- **FAQ**: https://kyanos.io/faq.html
- **eBPF Reference**: https://ebpf.io/
- **Cilium eBPF**: https://github.com/cilium/ebpf

---

## Related Projects

Kyanos development was inspired by the following projects:

- [eCapture](https://ecapture.cc/zh/) - SSL capture
- [pixie](https://github.com/pixie-io/pixie) - K8s observability
- [ptcpdump](https://github.com/mozillazg/ptcpdump) - Process-level tcpdump
