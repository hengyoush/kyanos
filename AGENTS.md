# Kyanos AGENTS.md

> 本文件为 AI Agent 提供项目背景、结构、编码规范和工作流程信息。

## 项目概述

**Kyanos** 是一个基于 eBPF 的网络问题分析工具，用于捕获和分析网络请求（HTTP、Redis、MySQL 等），帮助快速诊断网络相关问题，如慢查询、高流量和异常。

### 核心特性

1. **流量过滤**：支持按进程/容器、L7 协议、请求/响应大小、延迟等多维度过滤
2. **流量分析**：聚合指标，快速定位问题（如带宽占满时找出最大响应）
3. **内核级延迟详情**：可视化展示数据包从网卡到 socket 缓冲区的各阶段耗时
4. **SSL 自动解密**：自动解密 HTTPS 流量为明文
5. **零依赖**：单二进制文件，命令行交互

### 技术栈

- **语言**: Go 1.23+
- **内核技术**: eBPF (使用 cilium/ebpf 库)
- **UI**: Charmbracelet 生态 (Bubble Tea, Bubbles, Lipgloss)
- **CLI**: Cobra + Viper
- **支持协议**: HTTP, Redis, MySQL, Kafka, MongoDB, RocketMQ, DNS

---

## 项目结构

```
kyanos/
├── main.go                 # 入口文件，调用 cmd.Execute()
├── go.mod                  # Go 依赖管理
├── Makefile               # 构建脚本
├── bpf/                   # eBPF C 程序和头文件
│   ├── pktlatency.bpf.c   # 主 eBPF 程序
│   ├── openssl_*.bpf.c    # 各版本 OpenSSL uprobe
│   ├── gotls.bpf.c        # Go TLS uprobe
│   ├── *.h                # BPF 头文件
│   └── loader/            # BPF 加载器 (Go)
├── cmd/                   # CLI 命令定义
│   ├── root.go            # 根命令和全局 flags
│   ├── watch.go           # watch 子命令
│   ├── stat.go            # stat 子命令
│   └── *.go               # 其他协议命令
├── agent/                 # 核心 Agent 逻辑
│   ├── agent.go           # Agent 启动和主循环
│   ├── conn/              # 连接管理、事件处理
│   ├── protocol/          # 协议解析器
│   ├── analysis/          # 流量分析
│   ├── render/            # UI 渲染
│   └── metadata/          # 容器/K8s 元数据
├── common/                # 公共工具和类型
│   ├── log.go             # 日志系统
│   ├── utils.go           # 通用工具
│   └── *.go
├── version/               # 版本信息
├── vmlinux/               # 各架构的 vmlinux.h
├── libbpf/                # libbpf 子模块
└── docs/                  # 文档
```

---

## 构建系统

### 依赖要求

- **Go**: 1.23+
- **Clang**: 10.0+
- **LLVM**: 10.0+
- **Linux 头文件**: linux-tools-common, linux-tools-generic
- **其他**: pkgconf, libelf-dev

### 常用构建命令

```bash
# 开发构建（本地测试）
make build-bpf && make

# 生成带 BTF 的完整构建（用于低版本内核）
make build-bpf && make btfgen BUILD_ARCH=x86_64 ARCH_BPF_NAME=x86 && make

# 调试构建
make kyanos-debug

# 测试
make test

# 格式化代码
make format
```

### BPF 代码生成

项目使用 `go generate` 生成 BPF 骨架代码：

```bash
# 在 bpf/loader/loader.go 中定义
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ...

TARGET=amd64 go generate ./bpf/  # x86_64
TARGET=arm64 go generate ./bpf/  # arm64
```

---

## 代码规范

### Go 编码风格

1. **包命名**: 全小写，简短有意义，避免下划线
2. **文件命名**: 全小写，使用下划线分隔，如 `kern_event_handler.go`
3. **接口命名**: 动词+名词，如 `ProtocolStreamParser`
4. **错误处理**: 显式处理，使用 `common.DefaultLog` 记录
5. **日志**: 使用 `common.AgentLog`, `common.BPFLog` 等专用 logger

### 关键模式

#### Agent 启动流程

```go
// agent/agent.go: SetupAgent()
1. 检查 BPF 权限 (CAP_BPF)
2. 初始化 ConnManager
3. 初始化 ProcessorManager
4. 加载 BPF 程序 (loader.LoadBPF)
5. 启动事件拉取 goroutines
6. 启动渲染 UI
```

#### 协议解析器

```go
// agent/protocol/protocol.go

// 实现 ProtocolStreamParser 接口
type ProtocolStreamParser interface {
    Match(reqStreams, respStreams) []Record
    FindBoundary(streamBuffer, messageType, startPos) int
    ParseRequest(streamBuffer, messageType) *ParsedMessage
    // ...
}

// 注册解析器
func init() {
    ParsersMap[bpf.AgentTrafficProtocolTKProtocolXXX] = func() ProtocolStreamParser {
        return &XXXStreamParser{}
    }
}
```

#### eBPF Map 定义

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

## 测试

### 测试结构

```
agent/
├── agent_test.go              # Agent 测试
├── agent_utils_test.go        # 工具测试
└── protocol/
    └── http_test.go           # 协议解析测试
```

### 运行测试

```bash
# 所有测试
go test -v ./...

# 特定包测试
go test -v ./agent/...

# 性能测试
go test -bench=. ./...
```

---

## 常见问题

### 1. BPF 加载失败

- 检查内核版本（要求 3.10.0-957+ 或 4.14+）
- 检查 BTF 是否启用: `zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz`
- 使用 `--btf` 指定外部 BTF 文件

### 2. 容器相关功能不工作

- 确保有访问 Docker/Containerd/CRI 的权限
- 使用 `--docker-address`, `--containerd-address` 指定端点

### 3. SSL 解密失败

- 检查 OpenSSL 版本是否支持
- 确保进程有 ptrace 权限

---

## 贡献指南

### 添加新协议支持

1. 在 `bpf/protocol_inference.h` 添加协议检测逻辑
2. 在 `agent/protocol/` 创建解析器，实现 `ProtocolStreamParser`
3. 在 `cmd/` 添加对应的子命令
4. 添加测试用例

### 修改 BPF 代码

1. 修改 `.c` 或 `.h` 文件
2. 运行 `make build-bpf` 重新生成骨架代码
3. 测试验证

---

## 参考资源

- **文档**: https://kyanos.io/
- **GitHub**: https://github.com/hengyoush/kyanos
- **FAQ**: https://kyanos.io/faq.html
- **eBPF 参考**: https://ebpf.io/
- **Cilium eBPF**: https://github.com/cilium/ebpf

---

## 相关项目

Kyanos 开发过程中参考了以下项目：

- [eCapture](https://ecapture.cc/zh/) - SSL 捕获
- [pixie](https://github.com/pixie-io/pixie) - K8s 可观测性
- [ptcpdump](https://github.com/mozillazg/ptcpdump) - 进程级 tcpdump
