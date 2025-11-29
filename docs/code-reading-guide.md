# Kyanos 代码阅读指南

## 目录

- [项目概述](#项目概述)
- [目录结构](#目录结构)
- [推荐阅读顺序](#推荐阅读顺序)
- [主流程分析](#主流程分析)
- [eBPF 事件处理详解](#ebpf-事件处理详解)
- [关键数据结构](#关键数据结构)
- [关键代码位置索引](#关键代码位置索引)

---

## 项目概述

Kyanos 是一个基于 **eBPF** 的网络流量分析工具，主要功能包括：

- 捕获和分析 L7 层网络请求（HTTP、Redis、MySQL、Kafka、RocketMQ）
- 支持 SSL/TLS 自动解密
- 提供内核级别的延迟分析（网卡延迟、内核延迟、应用延迟）
- 支持按进程、容器、Pod 进行过滤
- 提供实时监控和统计分析两种模式

---

## 目录结构

```
kyanos/
├── main.go                  # 入口点（仅 7 行，调用 cmd.Execute()）
│
├── cmd/                     # CLI 命令处理（基于 Cobra 框架）
│   ├── root.go             # 根命令，定义全局 flags
│   ├── watch.go            # watch 模式：实时监控流量
│   ├── stat.go             # stat 模式：统计分析
│   ├── common.go           # 公共逻辑，startAgent() 函数
│   ├── http.go             # HTTP 协议过滤器
│   ├── redis.go            # Redis 协议过滤器
│   ├── mysql.go            # MySQL 协议过滤器
│   ├── kafka.go            # Kafka 协议过滤器
│   └── rocketmq.go         # RocketMQ 协议过滤器
│
├── agent/                   # 核心业务逻辑
│   ├── agent.go            # 主流程编排，SetupAgent() 函数
│   │
│   ├── conn/               # 连接跟踪和事件处理
│   │   ├── conntrack.go    # 连接状态机 Connection4
│   │   ├── processor.go    # 事件处理器 Processor
│   │   ├── kern_event_handler.go  # 内核事件处理
│   │   └── record_processor.go    # 记录处理器
│   │
│   ├── protocol/           # L7 协议解析器
│   │   ├── protocol.go     # 协议接口定义
│   │   ├── http.go         # HTTP 解析
│   │   ├── redis.go        # Redis 解析
│   │   ├── mysql/          # MySQL 解析
│   │   └── kafka/          # Kafka 解析
│   │
│   ├── analysis/           # 统计分析
│   │   ├── analysis.go     # 分析器主逻辑
│   │   ├── stat.go         # 统计计算
│   │   └── classfier.go    # 分类器
│   │
│   ├── render/             # UI 渲染
│   │   ├── watch/          # 实时监控 TUI
│   │   └── stat/           # 统计输出
│   │
│   └── metadata/           # 容器/K8s 元数据
│       ├── container/      # Docker、containerd 集成
│       └── k8s/            # Kubernetes 集成
│
├── bpf/                     # eBPF 程序和加载器
│   ├── loader/             # BPF 程序加载
│   │   └── loader.go       # LoadBPF() 函数
│   ├── events.go           # 事件读取和分发
│   ├── pktlatency.bpf.c    # 网络包延迟追踪
│   ├── gotls.bpf.c         # Go TLS 拦截
│   ├── openssl_*.bpf.c     # OpenSSL 拦截
│   └── data_common.h       # 共享数据结构
│
├── common/                  # 公共工具函数
│   ├── proc.go             # /proc 文件系统解析
│   ├── kernel_version.go   # 内核版本检测
│   └── utils.go            # 通用工具
│
└── vmlinux/                 # 预生成的 vmlinux.h（不同架构）
```

---

## 推荐阅读顺序

### 第一阶段：理解入口和主流程

| 顺序 | 文件 | 重点内容 |
|------|------|----------|
| 1 | `main.go` | 入口点，仅调用 `cmd.Execute()` |
| 2 | `cmd/root.go` | 命令行结构，全局 flags 定义 |
| 3 | `cmd/common.go` | `startAgent()` 函数，启动核心逻辑 |
| 4 | `agent/agent.go` | **核心文件**，`SetupAgent()` 编排整个流程 |

### 第二阶段：理解数据流

| 顺序 | 文件 | 重点内容 |
|------|------|----------|
| 5 | `bpf/loader/loader.go` | eBPF 程序加载过程 |
| 6 | `bpf/events.go` | 从内核读取事件的入口 |
| 7 | `agent/conn/processor.go` | 事件处理管道 |
| 8 | `agent/conn/conntrack.go` | **最重要**，连接状态机 |

### 第三阶段：理解协议解析

| 顺序 | 文件 | 重点内容 |
|------|------|----------|
| 9 | `agent/protocol/protocol.go` | 协议接口定义 |
| 10 | `agent/protocol/http.go` | HTTP 解析实现示例 |

### 第四阶段：理解输出渲染

| 顺序 | 文件 | 重点内容 |
|------|------|----------|
| 11 | `agent/render/watch/` | 实时监控 UI |
| 12 | `agent/analysis/analysis.go` | 统计分析逻辑 |

---

## 主流程分析

### 启动流程图

```
┌─────────────────────────────────────────────────────────────┐
│                      用户执行命令                            │
│           kyanos watch http --path /api --pids 1234         │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│    cmd/root.go → cmd/watch.go → cmd/common.go               │
│                  解析命令行参数，构建 AgentOptions            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                agent/agent.go: SetupAgent()                 │
│                                                             │
│    1. 权限检查（root/CAP_BPF）                               │
│    2. 初始化 ConnManager（连接管理）                          │
│    3. 初始化 ProcessorManager（事件处理）                     │
│    4. 加载 eBPF 程序                                         │
│    5. 启动事件读取器                                          │
│    6. 启动渲染/分析                                           │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              bpf/loader/loader.go: LoadBPF()                │
│                                                             │
│    - 检测内核版本和特性                                       │
│    - 加载 .bpf.o 字节码                                      │
│    - 附加 kprobes/uprobes/tracepoints                       │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      事件处理循环                            │
│                                                             │
│    eBPF (内核态) 捕获事件                                     │
│           │                                                 │
│           ▼ perf buffer                                     │
│    bpf/events.go 读取事件                                    │
│           │                                                 │
│           ▼ channels                                        │
│    agent/conn/processor.go 处理事件                          │
│           │                                                 │
│           ▼                                                 │
│    agent/conn/conntrack.go 连接状态机                        │
│           │                                                 │
│           ▼ 协议解析                                         │
│    agent/protocol/*.go                                      │
│           │                                                 │
│           ▼ Record                                          │
│    渲染输出 (watch UI / stat 统计)                           │
└─────────────────────────────────────────────────────────────┘
```

### SetupAgent() 核心步骤

```go
// agent/agent.go

func SetupAgent(options AgentOptions) {
    // 1. 权限和环境检查
    checkPermission()
    checkKernelVersion()

    // 2. 初始化连接管理器
    connManager := conn.NewConnManager()

    // 3. 初始化处理器管理器（多个 worker）
    processorManager := conn.NewProcessorManager(connManager, options)

    // 4. 加载 eBPF 程序
    bpfLoader.LoadBPF(options)

    // 5. 启动事件读取协程
    go bpf.PullSyscallDataEvents(ctx, processorManager.GetSyscallEventsChannels())
    go bpf.PullSslDataEvents(ctx, processorManager.GetSslEventsChannels())
    go bpf.PullConnDataEvents(ctx, processorManager.GetConnEventsChannels())
    go bpf.PullKernEvents(ctx, processorManager.GetKernEventsChannels())

    // 6. 启动渲染
    if options.WatchMode {
        watch.RunWatchRender()
    } else {
        analysis.CreateAnalyzer().Run()
    }
}
```

---

## eBPF 事件处理详解

### 整体架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                       内核空间 (eBPF)                            │
│                                                                 │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│   │  网络事件探针  │  │ 系统调用探针  │  │ SSL/TLS 探针 │         │
│   │  kprobes     │  │ tracepoints  │  │  uprobes     │         │
│   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
│          │                 │                 │                 │
│          ▼                 ▼                 ▼                 │
│   ┌─────────────────────────────────────────────────────┐     │
│   │           BPF Ring Buffers (Perf Event Array)       │     │
│   │                                                     │     │
│   │   Rb │ SyscallRb │ SslRb │ ConnEvtRb │ FirstPacketRb│     │
│   └─────────────────────────────────────────────────────┘     │
└────────────────────────────┬────────────────────────────────────┘
                             │ Perf Buffer
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   用户空间 - 事件读取层                           │
│                   bpf/events.go                                 │
│                                                                 │
│   ┌─────────────────────────────────────────────────────┐      │
│   │ PullKernEvents() │ PullSyscallDataEvents() │ ...    │      │
│   └─────────────────────────────────────────────────────┘      │
│                             │ channels (按 tgidfd 分发)         │
│                             ▼                                   │
│                   用户空间 - 处理层                              │
│                   agent/conn/processor.go                       │
│                                                                 │
│   ┌─────────────────────────────────────────────────────┐      │
│   │   Processor 1  │  Processor 2  │  ...  │ Processor N │      │
│   └─────────────────────────────────────────────────────┘      │
│                             │                                   │
│                             ▼                                   │
│                   用户空间 - 连接跟踪层                           │
│                   agent/conn/conntrack.go                       │
│                                                                 │
│   ┌─────────────────────────────────────────────────────┐      │
│   │             Connection4 (连接状态机)                 │      │
│   │                                                     │      │
│   │   - reqStreamBuffer (请求数据缓冲)                   │      │
│   │   - respStreamBuffer (响应数据缓冲)                  │      │
│   │   - StreamEvents (内核事件流)                        │      │
│   └─────────────────────────────────────────────────────┘      │
│                             │ Record                            │
│                             ▼                                   │
│                   输出层 (Watch UI / 统计分析)                   │
└─────────────────────────────────────────────────────────────────┘
```

### 事件类型

| 事件类型 | 结构体 | 来源 | 用途 |
|---------|--------|------|------|
| 内核事件 | `AgentKernEvt` | 网络协议栈各层 | 记录数据包时间戳，计算延迟 |
| 系统调用事件 | `SyscallEventData` | read/write/send/recv | 获取实际传输数据 |
| SSL 事件 | `SslData` | OpenSSL/Go TLS | 获取解密后的数据 |
| 连接事件 | `AgentConnEvtT` | connect/close | 连接生命周期管理 |
| 首包事件 | `AgentFirstPacketEvt` | 首个数据包 | 协议推断 |

### 核心数据结构

```go
// bpf/agent_x86_bpfel.go

// 内核事件 - 记录数据包在内核各阶段的时间戳
type AgentKernEvt struct {
    Ts        uint64       // 时间戳
    TsDelta   uint32       // 与上一阶段的时间差
    Seq       uint32       // TCP 序列号
    Len       uint32       // 数据长度
    Step      AgentStepT   // 当前阶段
    ConnIdS   ConnId       // 连接标识 (tgid_fd)
}

// 系统调用事件 - 包含实际数据
type SyscallEventData struct {
    SyscallEvent struct {
        Ke      AgentKernEvt
        BufSize uint32
    }
    Buf []byte  // 实际传输的数据
}

// 连接事件
type AgentConnEvtT struct {
    ConnInfo AgentConnInfoT  // 连接信息
    ConnType AgentConnTypeT  // CONNECT/CLOSE/PROTOCOL_INFER
    Ts       uint64          // 时间戳
}
```

### 内核事件阶段 (Step)

数据包在内核中经过的各个阶段：

**出方向 (Egress)**:
```
SSL_OUT → SYSCALL_OUT → TCP_OUT → IP_OUT → QDISC_OUT → DEV_OUT → NIC_OUT
```

**入方向 (Ingress)**:
```
NIC_IN → DEV_IN → IP_IN → TCP_IN → USER_COPY → SYSCALL_IN → SSL_IN
```

通过记录每个阶段的时间戳，可以精确计算：
- 网卡延迟
- 内核协议栈延迟
- Socket 缓冲区延迟
- 应用处理延迟

### 事件读取函数

**文件位置**: `bpf/events.go`

```go
// 读取内核网络事件
func PullKernEvents(ctx context.Context, channels []chan *AgentKernEvt, ...)

// 读取系统调用数据
func PullSyscallDataEvents(ctx context.Context, channels []chan *SyscallEventData, ...)

// 读取 SSL 数据
func PullSslDataEvents(ctx context.Context, channels []chan *SslData, ...)

// 读取连接事件
func PullConnDataEvents(ctx context.Context, channels []chan *AgentConnEvtT, ...)

// 读取首包事件
func PullFirstPacketEvents(ctx context.Context, channel chan *AgentFirstPacketEvt, ...)
```

**负载均衡**:
```go
// 根据 tgidfd (进程ID + 文件描述符) 分发到不同的 Processor
ch := channels[int(tgidfd) % len(channels)]
```

### Processor 事件处理

**文件位置**: `agent/conn/processor.go`

```go
type Processor struct {
    // 5 个事件输入通道
    connEvents         chan *AgentConnEvtT
    syscallEvents      chan *SyscallEventData
    sslEvents          chan *SslData
    kernEvents         chan *AgentKernEvt
    firstPacketsEvents chan *agentKernEvtWithConn

    // 临时缓冲区（等待 100ms 确保事件顺序）
    tempKernEvents    *RingBuffer  // 容量 1000
    tempSyscallEvents *RingBuffer  // 容量 1000
    tempSslEvents     *RingBuffer  // 容量 100
}
```

**主处理循环**:

```go
func (p *Processor) run() {
    ticker := time.NewTicker(100 * time.Millisecond)

    for {
        select {
        case evt := <-p.connEvents:
            p.handleConnEvent(evt)      // 处理连接事件

        case evt := <-p.syscallEvents:
            p.handleSyscallEvent(evt)   // 暂存到 tempSyscallEvents

        case evt := <-p.sslEvents:
            p.handleSslEvent(evt)       // 暂存到 tempSslEvents

        case evt := <-p.kernEvents:
            p.handleKernEvent(evt)      // 暂存到 tempKernEvents

        case <-ticker.C:
            // 每 100ms 处理超时的缓冲事件
            p.processTimedSyscallEvents()
            p.processTimedKernEvents()
            p.processTimedSslEvents()
        }
    }
}
```

### 事件处理流程

#### 1. 连接事件处理

```
ConnEvent
    │
    ├── CONNECT → 创建 Connection4，初始化缓冲区
    │
    ├── CLOSE → 标记连接关闭，清理资源
    │
    └── PROTOCOL_INFER → 协议识别成功
            │
            ▼
        回放 TempSyscallEvents
        回放 TempKernEvents
        回放 TempSslEvents
            │
            ▼
        正常处理后续事件
```

#### 2. 系统调用事件处理

```
SyscallEvent
    │
    ▼
Processor.handleSyscallEvent()
    │
    ▼
暂存到 tempSyscallEvents（等待 100ms）
    │
    ▼ (超时后)
processTimedSyscallEvents()
    │
    ▼
查找 Connection4 (by tgidfd)
    │
    ├── 协议未知? → 暂存到 Connection4.TempSyscallEvents
    │
    └── 协议已知 → Connection4.OnSyscallEvent()
            │
            ▼
        写入 reqStreamBuffer 或 respStreamBuffer
            │
            ▼
        parseStreamBuffer() → 协议解析
            │
            ▼
        匹配请求/响应 → 生成 Record
```

#### 3. 内核事件处理

```
KernEvent
    │
    ▼
记录数据包在内核各层的时间戳
    │
    ▼
添加到 Connection4.StreamEvents
    │
    ▼
用于计算延迟指标:
  - 网卡延迟 (NIC_IN → DEV_IN)
  - 内核延迟 (DEV_IN → TCP_IN)
  - Socket 延迟 (TCP_IN → SYSCALL_IN)
  - 应用延迟 (SYSCALL_IN → 响应)
```

### Connection4 连接状态机

**文件位置**: `agent/conn/conntrack.go`

```go
type Connection4 struct {
    // 连接标识
    LocalIp, RemoteIp     net.IP
    LocalPort, RemotePort uint16
    TgidFd                uint64  // 进程ID + 文件描述符

    // 协议信息
    Protocol              bpf.AgentTrafficProtocolT
    Role                  EndpointRole  // Client/Server/Unknown

    // 数据缓冲
    reqStreamBuffer       *buffer.StreamBuffer  // 请求数据 (1MB)
    respStreamBuffer      *buffer.StreamBuffer  // 响应数据 (1MB)

    // 内核事件流（用于延迟计算）
    StreamEvents          *KernEventStream

    // 消息队列
    ReqQueue              map[StreamId]*ParsedMessageQueue
    RespQueue             map[StreamId]*ParsedMessageQueue

    // TCP 握手状态
    TCPHandshakeStatus    struct {
        ConnectStartTs    uint64
        ServerSynReceived bool
        ClientAckSent     bool
    }
}
```

**核心方法**:

| 方法 | 位置 | 作用 |
|------|------|------|
| `OnKernEvent()` | conntrack.go:384 | 处理内核事件，跟踪 TCP 握手 |
| `OnSyscallEvent()` | conntrack.go:534 | 写入流缓冲，触发协议解析 |
| `OnSslDataEvent()` | conntrack.go:491 | 处理解密后的 SSL 数据 |
| `parseStreamBuffer()` | conntrack.go:579 | 协议消息解析 |

### 协议推断流程

```
首次收到数据
    │
    ▼
内核 infer_protocol() 分析首包内容
    │
    ├── HTTP: 检测 "GET ", "POST ", "HTTP/" 等
    ├── MySQL: 检测握手包特征
    ├── Redis: 检测 RESP 协议格式
    └── ...
    │
    ├── 识别成功 → 发送 PROTOCOL_INFER 事件
    │                   │
    │                   ▼
    │              更新 Connection4.Protocol
    │                   │
    │                   ▼
    │              回放暂存的事件
    │
    └── 识别失败 → Protocol = Unknown，跳过处理
```

**支持的协议**:
- HTTP / HTTP2
- MySQL
- PostgreSQL
- Redis
- MongoDB
- Kafka
- RocketMQ
- AMQP
- DNS
- NATS
- Cassandra (CQL)

### 事件丢失监控

```go
// bpf/events.go

var SyscallDataEventLostCnt int64  // 系统调用事件丢失计数
var SslDataEventLostCnt int64      // SSL 事件丢失计数
var ConnEventLostCnt int64         // 连接事件丢失计数
var KernEventLostCnt int64         // 内核事件丢失计数
```

当 Perf Buffer 溢出时会增加计数，可用于监控系统负载。

---

## 关键数据结构

### AgentOptions

**文件位置**: `agent/common/options.go`

运行时配置，包含所有过滤条件和模式设置。

### Connection4

**文件位置**: `agent/conn/conntrack.go`

TCP 连接状态机，管理连接的完整生命周期。

### Processor

**文件位置**: `agent/conn/processor.go`

事件处理器，负责接收和路由 eBPF 事件。

### Record

**文件位置**: `agent/protocol/`

请求-响应对，包含完整的协议信息和延迟数据。

### AgentObjects

**文件位置**: `bpf/`

eBPF 程序和 maps 的管理结构。

---

## 关键代码位置索引

### 启动流程

| 功能 | 文件 | 函数/位置 |
|------|------|----------|
| 程序入口 | `main.go` | `main()` |
| 命令解析 | `cmd/root.go` | `Execute()` |
| 启动 Agent | `cmd/common.go` | `startAgent()` |
| Agent 初始化 | `agent/agent.go` | `SetupAgent()` |
| BPF 加载 | `bpf/loader/loader.go` | `LoadBPF()` |

### 事件处理

| 功能 | 文件 | 函数/位置 |
|------|------|----------|
| 事件读取入口 | `bpf/events.go` | `PullKernEvents()` 等 |
| Processor 主循环 | `agent/conn/processor.go:174` | `run()` |
| 连接事件处理 | `agent/conn/processor.go:188` | `handleConnEvent()` |
| 系统调用处理 | `agent/conn/processor.go:433` | `handleSyscallEvent()` |

### 连接跟踪

| 功能 | 文件 | 函数/位置 |
|------|------|----------|
| 连接状态机 | `agent/conn/conntrack.go:29` | `Connection4` 结构体 |
| 内核事件处理 | `agent/conn/conntrack.go:384` | `OnKernEvent()` |
| 系统调用处理 | `agent/conn/conntrack.go:534` | `OnSyscallEvent()` |
| 协议解析 | `agent/conn/conntrack.go:579` | `parseStreamBuffer()` |

### 协议解析

| 功能 | 文件 | 函数/位置 |
|------|------|----------|
| 协议接口 | `agent/protocol/protocol.go` | `ProtocolStreamParser` |
| HTTP 解析 | `agent/protocol/http.go` | `ParseStreamBuffer()` |
| Redis 解析 | `agent/protocol/redis.go` | `ParseStreamBuffer()` |

### 内核事件流

| 功能 | 文件 | 函数/位置 |
|------|------|----------|
| 事件流管理 | `agent/conn/kern_event_handler.go` | `KernEventStream` |
| 添加事件 | `agent/conn/kern_event_handler.go` | `AddKernEvent()` |
| 查询事件 | `agent/conn/kern_event_handler.go` | `FindEventsBySeqAndLen()` |

---

## 快速入门建议

1. **先跑起来**：执行 `sudo ./kyanos watch http` 观察效果

2. **从主流程开始**：阅读 `agent/agent.go:SetupAgent()` 理解整体流程

3. **关注核心文件**：
   - `agent/conn/conntrack.go` - 连接状态机
   - `agent/conn/processor.go` - 事件处理
   - `bpf/events.go` - 事件读取

4. **eBPF 部分后看**：`bpf/*.bpf.c` 是内核态代码，理解 Go 部分后再深入

5. **调试技巧**：
   - 使用 `--debug` 参数开启调试日志
   - 观察事件丢失计数判断性能瓶颈
