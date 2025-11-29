# Kyanos eBPF E2E 测试指南

本文档详细介绍了 Kyanos 项目中 eBPF 程序的端到端（E2E）测试机制。

## 目录

1. [测试架构概述](#测试架构概述)
2. [测试目录结构](#测试目录结构)
3. [CI/CD 集成](#cicd-集成)
4. [Shell E2E 测试脚本](#shell-e2e-测试脚本)
5. [Go 单元测试](#go-单元测试)
6. [测试工具函数](#测试工具函数)
7. [多内核版本测试](#多内核版本测试)
8. [协议测试](#协议测试)
9. [容器过滤测试](#容器过滤测试)
10. [编写新测试](#编写新测试)

---

## 测试架构概述

Kyanos 采用多层次测试策略，确保 eBPF 程序在不同环境下的正确性：

```
┌─────────────────────────────────────────────────────────────┐
│                    GitHub Actions CI/CD                      │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    构建阶段 (Build)                      ││
│  │  • 编译 eBPF 程序 (make build-bpf)                       ││
│  │  • 构建 Go 二进制 (make)                                 ││
│  └─────────────────────────────────────────────────────────┘│
│                              ↓                               │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              E2E 测试阶段 (8个内核版本并行)              ││
│  │  • 4.19, 5.4, 5.10, 5.15, 6.1, 6.6, bpf, bpf-next       ││
│  │  • 使用 little-vm-helper 创建 VM                        ││
│  │  • 执行 20+ Shell 测试脚本                              ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    本地测试环境                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Go 单元测试  │  │ Shell E2E    │  │ K8s 测试     │      │
│  │  (agent_test) │  │ 测试脚本     │  │ (Kind)       │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### 测试类型

| 类型 | 描述 | 位置 |
|------|------|------|
| **Go 单元测试** | 测试 eBPF 事件捕获、协议解析 | `agent/*_test.go` |
| **Shell E2E 测试** | 端到端协议和过滤功能测试 | `testdata/test_*.sh` |
| **K8s 集成测试** | Kubernetes Pod 监控测试 | `testdata/run_k8s_test.sh` |
| **权限测试** | CAP_BPF/CAP_SYS_ADMIN 测试 | `testdata/run_cap_bpf_test.sh` |

---

## 测试目录结构

```
kyanos/
├── .github/workflows/
│   ├── test.yml                    # 主 E2E 测试工作流
│   ├── build_verification.yml      # 构建验证
│   └── release-test.yml            # 发布测试
├── agent/
│   ├── agent_test.go               # 主要单元测试 (1200+ 行)
│   └── agent_utils_test.go         # 测试辅助函数
├── testdata/
│   ├── common.sh                   # 共享测试工具函数
│   ├── run_e2e.sh                  # 本地 E2E 测试运行器
│   ├── run_k8s_test.sh             # K8s 测试运行器
│   ├── run_cap_bpf_test.sh         # 权限测试运行器
│   ├── test_*.sh                   # 25+ 具体测试脚本
│   ├── test_k8s.yaml               # K8s Pod 清单
│   └── nginx_https.conf            # Nginx HTTPS 配置
└── bpf/
    ├── loader/loader_test.go       # BPF 加载器测试
    └── prog_test.go                # 程序反射测试
```

---

## CI/CD 集成

### GitHub Actions 工作流

**文件**: `.github/workflows/test.yml`

#### 工作流触发条件

```yaml
on:
  workflow_dispatch:
  push:
    branches: [ "main", "dev", "feature/*", "unstable" ]
  pull_request:
    branches: [ "main", "dev", "feature/*", "unstable" ]
```

#### 构建阶段

```yaml
build:
  runs-on: ubuntu-22.04
  steps:
    - uses: actions/checkout@v4.2.2
      with:
        submodules: recursive
    - name: Set up Go
      uses: actions/setup-go@v5.3.0
      with:
        go-version: '1.22.4'
    - name: Build
      run: |
        make clean && make build-bpf && make
```

#### E2E 测试矩阵

```yaml
e2e-test:
  needs: build
  strategy:
    fail-fast: false
    matrix:
      kernel:
        - '4.19-20240912.022020'
        - '5.4-20240912.022020'
        - '5.10-20240912.022020'
        - '5.15-20240912.022020'
        - '6.1-20240912.022020'
        - '6.6-20240912.022020'
        - 'bpf-20240912.022020'
        - 'bpf-next-20240912.022020'
  timeout-minutes: 30
```

#### VM 配置 (使用 Cilium little-vm-helper)

```yaml
- name: Provision LVH VMs
  uses: cilium/little-vm-helper@c44c1221b104ee02ec0235211f7ace3c88eb11a2
  with:
    test-name: kyanos-test
    image-version: ${{ matrix.kernel }}
    cpu: 2
    mem: '4G'
    host-mount: ./
    install-dependencies: 'true'
```

---

## Shell E2E 测试脚本

### 通用测试工具

**文件**: `testdata/common.sh`

```bash
#!/usr/bin/env bash

# 检查模式是否存在于文件中
function check_patterns_in_file() {
    local file_path=$1
    local pattern=$2
    if ! grep -q "$pattern" "$file_path"; then
        echo "Pattern '$pattern' not found in file '$file_path'." >&2
        exit 1
    fi
}

# 检查模式不存在于文件中
function check_patterns_not_in_file() {
    local file_path=$1
    local pattern=$2
    if grep -q "$pattern" "$file_path"; then
        echo "Pattern '$pattern' found in file '$file_path'." >&2
        exit 1
    fi
}

# 检查文件最后N行中的模式
function check_patterns_in_file_with_last_lines() {
    local file_path=$1
    local pattern=$2
    local last_lines=$3
    if ! tail -n $last_lines "$file_path" | grep -q "$pattern"; then
        echo "Pattern '$pattern' not found in file '$file_path' in last $last_lines lines." >&2
        exit 1
    fi
}

# 检查时间详情是否完整 (无异常时间戳)
function check_time_detail_completed() {
    filename=$1
    check_patterns_not_in_file "$filename" '\-0\.000'
    check_patterns_not_in_file "$filename" '1970\-01'
    check_patterns_not_in_file "$filename" 'count]=0'
}
```

### 测试脚本模式

每个测试脚本遵循相同的模式：

```bash
#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"                              # kyanos 命令
DOCKER_REGISTRY="$2"                  # 可选的镜像仓库
FILE_PREFIX="/tmp/kyanos"
LNAME="${FILE_PREFIX}_test_name.log"

function test_function_name() {
    # 1. 准备环境 (启动服务、拉取镜像等)
    docker pull $IMAGE_NAME
    cid=$(docker run -d -p PORT:PORT $IMAGE_NAME)

    # 2. 启动 kyanos 监控 (后台运行，带超时)
    timeout 30 ${CMD} watch --debug-output PROTOCOL --remote-ports PORT 2>&1 | tee "${LNAME}" &

    # 3. 生成测试流量
    sleep 10
    # ... 发送请求 ...

    # 4. 等待并清理
    docker rm -f $cid || true
    wait

    # 5. 验证结果
    cat "${LNAME}"
    check_patterns_in_file "${LNAME}" "expected_pattern"
}

function main() {
    test_function_name
}

main
```

### 测试脚本列表

| 脚本 | 测试内容 |
|------|----------|
| `test_http_gzip.sh` | HTTP gzip 压缩响应解析 |
| `test_https.sh` | HTTPS/TLS 流量捕获 |
| `test_kafka.sh` | Kafka 协议解析 (客户端/服务端) |
| `test_redis.sh` | Redis 协议解析 (客户端/服务端) |
| `test_mysql.sh` | MySQL 协议解析 |
| `test_rocketmq.sh` | RocketMQ 协议解析 |
| `test_gotls.sh` | Go TLS (uprobe) 测试 |
| `test_base.sh` | 基础功能测试 |
| `test_side.sh` | 客户端/服务端视角测试 |
| `test_kern_evt.sh` | 内核事件捕获测试 |
| `test_filter_by_comm.sh` | 按进程名过滤 |
| `test_filter_by_l4.sh` | 按 L3/L4 信息过滤 |
| `test_docker_filter_by_container_id.sh` | Docker 容器 ID 过滤 |
| `test_docker_filter_by_container_name.sh` | Docker 容器名过滤 |
| `test_docker_filter_by_pid.sh` | Docker PID 过滤 |
| `test_containerd_filter_by_container_id.sh` | Containerd 容器 ID 过滤 |
| `test_containerd_filter_by_container_name.sh` | Containerd 容器名过滤 |
| `test_truncated_data.sh` | 截断数据解析测试 |
| `test_ipv6.sh` | IPv6 支持测试 |
| `test_k8s.sh` | Kubernetes Pod 监控 |

---

## Go 单元测试

### 测试框架

**文件**: `agent/agent_test.go`

```go
package agent_test

import (
    "kyanos/bpf"
    "kyanos/agent/conn"
    "testing"
)

func TestMain(m *testing.M) {
    customAgentOptions = ac.AgentOptions{}
    retCode := m.Run()
    tearDown()
    os.Exit(retCode)
}
```

### 核心测试模式

#### 1. eBPF 程序选择性加载

```go
func TestConnectSyscall(t *testing.T) {
    connEventList := make([]bpf.AgentConnEvtT, 0)
    agentStopper := make(chan os.Signal, 1)

    // 只加载 connect 相关的 eBPF 程序
    StartAgent(
        []bpf.AttachBpfProgFunction{
            bpf.AttachSyscallConnectEntry,
            bpf.AttachSyscallConnectExit,
        },
        &connEventList,
        nil,  // syscallEventList
        nil,  // kernEventList
        agentStopper)

    defer func() {
        agentStopper <- MySignal{}
    }()

    // 生成测试流量
    sendTestHttpRequest(t, SendTestHttpRequestOptions{
        disableKeepAlived: true,
        targetUrl: "http://www.baidu.com",
    })

    // 断言捕获的事件
    time.Sleep(1 * time.Second)
    connectEvent := findInterestedConnEvent(t, connEventList, ...)
    AssertConnEvent(t, connectEvent, ConnEventAssertions{
        expectPid:             uint32(os.Getpid()),
        expectRemotePort:      80,
        expectConnEventType:   bpf.AgentConnTypeTKConnect,
    })
}
```

#### 2. 可用的 eBPF 程序附加函数

```go
// Syscall 相关
bpf.AttachSyscallConnectEntry
bpf.AttachSyscallConnectExit
bpf.AttachSyscallReadEntry
bpf.AttachSyscallReadExit
bpf.AttachSyscallWriteEntry
bpf.AttachSyscallWriteExit
bpf.AttachSyscallCloseEntry
bpf.AttachSyscallCloseExit
bpf.AttachSyscallAcceptEntry
bpf.AttachSyscallAcceptExit
bpf.AttachSyscallRecvfromEntry
bpf.AttachSyscallRecvfromExit
bpf.AttachSyscallSendtoEntry
bpf.AttachSyscallSendtoExit
bpf.AttachSyscallReadvEntry
bpf.AttachSyscallReadvExit
bpf.AttachSyscallWritevEntry
bpf.AttachSyscallWritevExit
bpf.AttachSyscallRecvMsgEntry
bpf.AttachSyscallRecvMsgExit
bpf.AttachSyscallSendMsgEntry
bpf.AttachSyscallSendMsgExit

// 内核探针
bpf.AttachKProbeSecuritySocketSendmsgEntry
bpf.AttachKProbeSecuritySocketRecvmsgEntry

// Tracepoint
bpf.AttachTracepointNetifReceiveSkb

// XDP (高内核版本)
bpf.AttachXdp
```

#### 3. 多层内核事件测试

```go
func TestExistedConn(t *testing.T) {
    StartEchoTcpServerAndWait()

    // 在启动 kyanos 前建立连接
    connection := WriteToEchoTcpServerAndReadResponse(...)

    // 启动 agent
    StartAgent(nil, &connEventList, &syscallEventList, &kernEventList, ...)

    // 通过已存在的连接发送数据
    WriteToEchoTcpServerAndReadResponse(..., existedConnection)

    // 验证多层内核事件
    assert.True(t, len(findInterestedKernEvents(..., bpf.AgentStepTIP_OUT)) > 0)
    assert.True(t, len(findInterestedKernEvents(..., bpf.AgentStepTDEV_OUT)) > 0)
    assert.True(t, len(findInterestedKernEvents(..., bpf.AgentStepTUSER_COPY)) > 0)
}
```

### 测试用例分类

| 测试函数 | 测试内容 |
|----------|----------|
| `TestConnectSyscall` | connect 系统调用捕获 |
| `TestCloseSyscall` | close 系统调用捕获 |
| `TestAccept` | accept 系统调用捕获 |
| `TestExistedConn` | 已存在连接的监控 |
| `TestReadSyscall` | read 系统调用捕获 |
| `TestWriteSyscall` | write 系统调用捕获 |
| `TestRecvFrom` | recvfrom 系统调用 |
| `TestSentTo` | sendto 系统调用 |
| `TestReadv` | readv 系统调用 |
| `TestWritev` | writev 系统调用 |
| `TestRecvmsg` | recvmsg 系统调用 |
| `TestSendmsg` | sendmsg 系统调用 |
| `TestIpXmit` | IP 层发送 |
| `TestDevQueueXmit` | QDISC 层 |
| `TestDevHardStartXmit` | NIC 层 |
| `TestTracepointNetifReceiveSkb` | 接收路径 |
| `TestIpRcvCore` | IP 接收 |
| `TestTcpV4DoRcv` | TCP 接收 |
| `TestSkbCopyDatagramIter` | 用户空间拷贝 |
| `TestSslEventsCanRelatedToKernEvents` | SSL 事件关联 |

---

## 测试工具函数

### agent_utils_test.go 辅助函数

#### StartAgent - 启动测试 Agent

```go
func StartAgent(
    bpfAttachFunctions []bpf.AttachBpfProgFunction,  // 要加载的 eBPF 程序
    connEventList *[]bpf.AgentConnEvtT,              // 连接事件收集
    syscallEventList *[]bpf.SyscallEventData,        // 系统调用事件收集
    kernEventList *[]bpf.AgentKernEvt,               // 内核事件收集
    connManagerInitHook func(*conn.ConnManager),     // 连接管理器初始化钩子
    agentStopper chan os.Signal,                     // 停止信号
)
```

#### Echo TCP 服务器

```go
// 启动 Echo 服务器
func StartEchoTcpServerAndWait()

// 发送数据并读取响应
func WriteToEchoTcpServerAndReadResponse(options WriteToEchoServerOptions) net.Conn

type WriteToEchoServerOptions struct {
    t                 *testing.T
    server            string
    message           string
    messageSlice      []string
    readResponse      bool
    writeSyscall      WriteSyscallType  // Write, SentTo, Writev, Sendmsg
    readSyscall       ReadSyscallType   // Read, RecvFrom, Readv, Recvmsg
    keepConnection    bool
    existedConnection net.Conn
}
```

#### 事件查找函数

```go
// 查找连接事件
func findInterestedConnEvent(t *testing.T, connEventList []bpf.AgentConnEvtT,
    options FindInterestedConnEventOptions) []bpf.AgentConnEvtT

// 查找系统调用事件
func findInterestedSyscallEvents(t *testing.T, syscallEventList []bpf.SyscallEventData,
    options FindInterestedSyscallEventOptions) []bpf.SyscallEventData

// 查找内核事件
func findInterestedKernEvents(t *testing.T, kernEventList []bpf.AgentKernEvt,
    options FindInterestedKernEventOptions) []bpf.AgentKernEvt

// 查找 SSL 事件
func findInterestedSslEvents(t *testing.T, sslEventList []bpf.SslData,
    options FindInterestedSyscallEventOptions) []bpf.SslData
```

#### 断言函数

```go
// 断言连接事件
func AssertConnEvent(t *testing.T, event bpf.AgentConnEvtT, assert ConnEventAssertions)

type ConnEventAssertions struct {
    expectPid             uint32
    expectLocalPort       int
    expectRemotePort      int
    expectLocalAddrFamily uint16
    expectRemoteFamily    uint16
    expectConnEventType   bpf.AgentConnTypeT
    expectReadBytes       uint64
    expectWriteBytes      uint64
}

// 断言内核事件
func AssertKernEvent(t *testing.T, event *bpf.AgentKernEvt, conditions KernDataEventAssertConditions)

// 断言系统调用事件
func AssertSyscallEventData(t *testing.T, event bpf.SyscallEventData,
    conditions SyscallDataEventAssertConditions)
```

---

## 多内核版本测试

### 支持的内核版本

| 版本 | BTF 支持 | 特殊处理 |
|------|----------|----------|
| 4.19 | 需要外部 BTF | 从 btfhub 下载 BTF 文件 |
| 5.4 | 需要外部 BTF | 从 btfhub 下载 BTF 文件 |
| 5.10+ | 内置 BTF | 直接使用 `/sys/kernel/btf/vmlinux` |
| bpf/bpf-next | 内置 BTF | 最新 eBPF 特性测试 |

### BTF 处理逻辑

```yaml
# 对于 4.x 内核，需要下载外部 BTF 文件
- name: download btf file
  if: ${{ startsWith(matrix.kernel, '4.') }}
  run: |
    img=quay.io/lvh-images/kernel-images:${{ matrix.kernel }}
    docker pull $img
    id=$(docker create $img)
    mkdir data/
    docker cp $id:/data/kernels data/

- name: copy btf file
  if: ${{ startsWith(matrix.kernel, '4.') }}
  cmd: |
    sudo mkdir -p /var/lib/kyanos/btf/
    sudo cp /host/data/kernels/4.*/boot/btf-4.* /var/lib/kyanos/btf/current.btf
```

### 内核版本特定测试

```yaml
# 某些测试只在特定内核版本运行
- name: Test Truncated Data parsing
  if: ${{ !contains(fromJSON('["4.19-...", "5.4-..."]'), matrix.kernel) }}

# K8s 测试只在 6.x 内核运行
- name: Test k8s
  if: ${{ startsWith(matrix.kernel, '6.') }}

# CAP_BPF 测试 (5.8+ 内核)
- name: Test CAP_BPF privilege check
  if: ${{ !contains(fromJSON('["4.19-...", "5.4-..."]'), matrix.kernel) }}

# CAP_SYS_ADMIN 测试 (旧内核)
- name: Test CAP_SYS_ADMIN privilege check
  if: contains(fromJSON('["4.19-...", "5.4-..."]'), matrix.kernel)
```

---

## 协议测试

### HTTP 测试

**文件**: `testdata/test_https.sh`

```bash
function test_http_plain_client() {
    pip install --break-system-packages requests || true
    timeout 30 python3 ./testdata/request_https.py 60 'https://httpbin.org/headers' &
    sleep 10
    timeout 30 ${CMD} watch --debug-output http --remote-ports 443 2>&1 | tee "${HTTPS_CLIENT_LNAME}" &
    wait
    cat "${HTTPS_CLIENT_LNAME}" | grep "httpbin"
}

function test_https_nginx_server() {
    # 生成自签名证书
    openssl genrsa -out ${TEST_DIR}/nginx.key 2048
    openssl req -new -x509 -key ${TEST_DIR}/nginx.key -out ${TEST_DIR}/nginx.crt -days 365

    # 启动 nginx HTTPS 服务器
    cid=$(docker run --rm -d -p 1443:1443 \
        -v ./testdata/nginx_https.conf:/etc/nginx/nginx.conf:ro \
        -v ${TEST_DIR}:${TEST_DIR} nginx:latest)

    timeout 30 ${CMD} watch --debug-output http --local-ports 1443 2>&1 | tee "${LNAME}" &
    sleep 20
    curl -k https://localhost:1443 || true
    wait
    check_patterns_in_file "${LNAME}" "[request]"
}
```

### Kafka 测试

**文件**: `testdata/test_kafka.sh`

```bash
function test_kafka_client() {
    docker pull apache/kafka:3.9.0
    cid=$(docker run -d -p 9092:9092 apache/kafka:3.9.0)
    sleep 20

    # 创建 topic
    docker exec $cid bash -c "/opt/kafka/bin/kafka-topics.sh --create --topic quickstart-events --bootstrap-server localhost:9092"

    # 启动 kyanos 监控
    timeout 30 ${CMD} watch --debug-output kafka --remote-ports 9092 2>&1 | tee "${CLIENT_LNAME}" &
    sleep 10

    # 发送消息
    docker exec $cid bash -c "cat /opt/kafka/bin/kafka-console-producer.sh | /opt/kafka/bin/kafka-console-producer.sh --topic quickstart-events --bootstrap-server localhost:9092"

    wait
    # 验证捕获到 Kafka API 请求
    cat "${CLIENT_LNAME}" | grep '[request]' | grep 'Apikey:' | grep 'Foundation'
}
```

### Redis 测试

**文件**: `testdata/test_redis.sh`

```bash
function test_redis_client() {
    docker pull redis:7.0.14
    cid=$(docker run --name test-redis -p 6379:6379 -d redis:7.0.14)

    timeout 30 ${CMD} watch --debug-output redis --remote-ports 6379 2>&1 | tee "${CLIENT_LNAME}" &
    sleep 10

    # 发送 Redis 命令
    redis-cli -r 5 -i 0.3 hget a key
    wait

    check_patterns_in_file "${CLIENT_LNAME}" "HGET"
}
```

---

## 容器过滤测试

### Docker 容器 ID 过滤

**文件**: `testdata/test_docker_filter_by_container_id.sh`

```bash
function test_docker_filter_by_container_id() {
    docker pull busybox:1
    cid1=$(docker run --rm -it -d busybox:1 sh -c 'sleep 10; wget -T 10 http://www.baidu.com')

    # 使用容器 ID 过滤
    timeout 30 ${CMD} watch --debug-output http --container-id=${cid1} 2>&1 | tee "${LNAME}" &
    sleep 10
    wait

    check_patterns_in_file "${LNAME}" "baidu.com"
}
```

### Kubernetes Pod 监控

**文件**: `testdata/run_k8s_test.sh`

```bash
# 使用 Kind 创建集群
kind create cluster --image kindest/node:v1.27.3

# 加载镜像
kind load docker-image alpine:3.18

# 复制 kyanos 和测试文件到集群节点
sudo docker cp /host/kyanos/kyanos kind-control-plane:/
sudo docker cp ./testdata/test_k8s.yaml kind-control-plane:/
sudo docker cp ./testdata/test_k8s.sh kind-control-plane:/

# 执行测试
sudo docker exec kind-control-plane sh -c 'bash /test_k8s.sh /kyanos /test_k8s.yaml'
```

**测试脚本**: `testdata/test_k8s.sh`

```bash
function test() {
    kubectl apply -f "${NEW_TEST_YAML}"
    kubectl wait --for condition=Ready pod/test-kyanos

    # 使用 pod 名称过滤
    timeout 20 ${CMD} watch --debug-output http --pod-name test-kyanos 2>&1 | tee "${LNAME}" &
    wait

    cat "${LNAME}" | grep "baidu.com"
}
```

---

## 编写新测试

### Shell E2E 测试模板

```bash
#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
DOCKER_REGISTRY="$2"
FILE_PREFIX="/tmp/kyanos"
LNAME="${FILE_PREFIX}_your_test.log"

function test_your_feature() {
    # 1. 设置镜像名称
    if [ -z "$DOCKER_REGISTRY" ]; then
        IMAGE_NAME="your-image:tag"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/your-image:tag"
    fi

    # 2. 启动测试服务
    docker pull "$IMAGE_NAME"
    cid=$(docker run -d -p PORT:PORT "$IMAGE_NAME")
    export cid

    # 3. 启动 kyanos 监控
    timeout 30 ${CMD} watch --debug-output PROTOCOL --remote-ports PORT 2>&1 | tee "${LNAME}" &

    # 4. 等待服务就绪
    sleep 10

    # 5. 生成测试流量
    # ... your test traffic generation ...

    # 6. 清理
    docker rm -f $cid || true
    wait

    # 7. 验证结果
    cat "${LNAME}"
    check_patterns_in_file "${LNAME}" "expected_pattern"
}

function main() {
    test_your_feature
}

main
```

### Go 单元测试模板

```go
func TestYourFeature(t *testing.T) {
    // 1. 准备事件收集列表
    connEventList := make([]bpf.AgentConnEvtT, 0)
    syscallEventList := make([]bpf.SyscallEventData, 0)
    kernEventList := make([]bpf.AgentKernEvt, 0)
    agentStopper := make(chan os.Signal, 1)

    // 2. 启动 Agent，选择性加载 eBPF 程序
    StartAgent(
        []bpf.AttachBpfProgFunction{
            bpf.AttachSyscallConnectEntry,
            bpf.AttachSyscallConnectExit,
            // ... 其他需要的程序
        },
        &connEventList,
        &syscallEventList,
        &kernEventList,
        nil,
        agentStopper)

    defer func() {
        agentStopper <- MySignal{}
    }()

    // 3. 生成测试流量
    // ... your test traffic ...

    // 4. 等待事件收集
    time.Sleep(1 * time.Second)

    // 5. 查找并验证事件
    events := findInterestedConnEvent(t, connEventList, FindInterestedConnEventOptions{
        findByRemotePort: true,
        remotePort:       YOUR_PORT,
        throw:            true,
    })

    // 6. 断言
    assert.Equal(t, 1, len(events))
    AssertConnEvent(t, events[0], ConnEventAssertions{
        expectPid:        uint32(os.Getpid()),
        expectRemotePort: YOUR_PORT,
    })
}
```

### 添加到 CI 工作流

在 `.github/workflows/test.yml` 中添加新测试步骤：

```yaml
- name: Test Your Feature
  uses: cilium/little-vm-helper@c44c1221b104ee02ec0235211f7ace3c88eb11a2
  with:
    provision: 'false'
    cmd: |
      set -ex
      uname -a
      cat /etc/issue
      if [ -f "/var/lib/kyanos/btf/current.btf" ]; then
          bash /host/testdata/test_your_feature.sh 'sudo /host/kyanos/kyanos $kyanos_log_option --btf /var/lib/kyanos/btf/current.btf'
      else
          bash /host/testdata/test_your_feature.sh 'sudo /host/kyanos/kyanos $kyanos_log_option'
      fi
```

---

## 运行测试

### 本地运行 Go 单元测试

```bash
# 需要 root 权限运行 eBPF 测试
sudo go test -v ./agent/...
```

### 本地运行 Shell E2E 测试

```bash
# 构建 kyanos
make clean && make build-bpf && make

# 运行单个测试
sudo bash testdata/test_redis.sh './kyanos'

# 使用调试选项
sudo bash testdata/test_redis.sh './kyanos --bpf-event-log-level 5 --conntrack-log-level 5 --agent-log-level 5'
```

### 运行 K8s 测试 (需要 Kind)

```bash
bash testdata/run_k8s_test.sh "" 1
```

---

## 调试技巧

### 启用详细日志

```bash
kyanos --bpf-event-log-level 5 --conntrack-log-level 5 --agent-log-level 5
```

### 检查 eBPF 程序加载

```bash
# 查看已加载的 eBPF 程序
bpftool prog list

# 查看 eBPF maps
bpftool map list
```

### 验证 BTF 支持

```bash
# 检查内核是否有内置 BTF
ls -la /sys/kernel/btf/vmlinux

# 检查外部 BTF 文件
ls -la /var/lib/kyanos/btf/
```

---

## 总结

Kyanos 的 E2E 测试框架提供了：

1. **全面的内核版本覆盖** - 从 4.19 到最新 bpf-next
2. **多协议支持测试** - HTTP、HTTPS、Kafka、Redis、MySQL、RocketMQ
3. **容器运行时兼容性** - Docker、Containerd、Kubernetes
4. **灵活的测试粒度** - 从单个系统调用到完整协议解析
5. **自动化 CI/CD 集成** - 每次提交自动运行完整测试套件

通过这套完善的测试体系，Kyanos 确保了 eBPF 程序在各种生产环境中的可靠性和正确性。
