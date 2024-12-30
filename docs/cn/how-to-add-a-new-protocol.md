# 如何为 kyanos 贡献新的协议

## 背景

kyanos 需要捕获协议消息组成请求响应对以供终端展示，因此 kyanos 需要每个协议的协议解析代码，目前支持 HTTP、MySQL 和 Redis，将来会支持更多。本文将阐述 kyanos 协议解析的整体架构，以协助开发新的协议。

## 协议解析流程总览

![kyanos protocol parse flow](/protocol-parse-flow.png)

从左边看起，kyanos 在 read、write 等系统调用上插桩，获取应用进程读写的数据，将其通过 perf
event buffer 发送到用户空间。

用户空间则根据这个连接是客户端侧还是服务端侧，分别放到 reqStreamBuffer 或者 respStreamBuffer 里。这些数据是单纯的应用协议数据，没有协议头。

kyanos 会使用相应协议的解析器解析放到 streamBuffer 的数据，然后关联解析后的请求和响应，最后根据协议的需要再进行 Full
Body 解析，生成一个“记录”（record）。

## 一些术语

Message：协议的最基本数据单元，通常有一个 header 和 body。

Request /
Response: 请求或响应由一起发送的一个或多个 Message 组成，这些 Message 在一起表示一个消息（_Note: 对于简单的协议比如 HTTP1.1 来说，一个 Request/Response 可能只对应一个 Message，但对于像 MySQL 这种复杂的协议，多个 Message 组合起来才对应一个 Request/Response_）

Record：Record 代表一个匹配完成的请求响应对。

## Step.0-准备工作

我们需要做以下几个事情：

1. 实现用户态协议解析
   1. 定义协议消息类型（即请求和响应的结构）
   2. 实现一个 `Parser`, 具体来说需要实现 `ProtocolStreamParser`
      接口，该接口实现了协议解析和请求响应匹配等的具体逻辑。
2. 实现内核态的协议推断逻辑。
3. 增加命令行子命令，实现过滤逻辑。
4. 增加 e2e 测试。

## Step.1-定义协议消息类型

在/agent/protocol 目录下新建一个目录，名称为协议名称，例如：kafka。

### 定义 Message

一般来说，你要实现的协议会存在一个通用的 Header，这个 Header 会包含一些元数据，比如一个标志位记录其是请求还是响应，像这些信息你需要存储到你定义的 Message 的字段里，比如 MySQL 协议定义的：

```go
type MysqlPacket struct {
	FrameBase
	seqId byte
	msg   string
	cmd   int
	isReq bool
}
```

一般来说，Message 或者下面的 Request/Response 都需要嵌入一个 FrameBase，FrameBase 定义如下，包含了一些基本信息：

```go
type FrameBase struct {
	timestampNs uint64
	byteSize    int
	seq         uint64
}
```

而对于 HTTP 等简单的协议来说，由于其一个 Message 就对应一个请求或响应，没有必要进行 Full
Body 解析，因此也就没必要定义一个 Message 了，直接定义 Request 和 Response 就可以。

### 定义请求和响应

请求和响应在 Message 的上层，由一个或多个 Message 组成。`struct Request` 或
`struct Response`
应包含特定于请求/响应的数据, 并且应该实现 ParsedMessage 接口，接口定义如下：

```go
type ParsedMessage interface {
	FormatToString() string
	FormatToSummaryString() string
	TimestampNs() uint64
	ByteSize() int
	IsReq() bool
	Seq() uint64
}
```

| 方法名             | 作用                                                                     |
| ------------------ | ------------------------------------------------------------------------ |
| `FormatToString()` | 将消息格式化为字符串表示形式。                                           |
| `TimestampNs()`    | 返回消息的时间戳（以纳秒为单位）。                                       |
| `ByteSize()`       | 返回消息的字节大小。                                                     |
| `IsReq()`          | 判断消息是否为请求。                                                     |
| `Seq()`            | 返回消息的字节流序列号, 可以从 `streamBuffer.Head().LeftBoundary()` 获取。 |

HTTP 的例子：

```go
type ParsedHttpRequest struct {
	FrameBase
	Path   string
	Host   string
	Method string

	buf []byte
}
```

> Note. 在 `protocol.BinaryDecoder` 中 `BinaryDecoder`
> 类提供了一些方便的实用程序函数，用于从缓冲区中提取字符、字符串或整数。在下面的实现 ParseFrame、FindFrameBoundary 和 Full
> Body 解析时，我们应该使用这些函数。

## Step.2-实现协议解析

定义好请求响应类型之后，就可以开始实现解析流程了，具体来说需要实现接口：`ProtocolStreamParser`

```go
type ProtocolStreamParser interface {
	ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult
	FindBoundary(streamBuffer *buffer.StreamBuffer, messageType MessageType, startPos int) int
	Match(reqStream *[]ParsedMessage, respStream *[]ParsedMessage) []Record
}
```

- ParseStream: 解析 Message
- FindBoundary: 寻找 Message 边界
- Match: ReqResp 匹配
- Full Body Parse(可选): Full Body 解析

### ParseStream (Buffer -> Message/ReqResp)

ParseStream 从网络数据解析出来 Message 或者直接解析出来 ReqResp。

```go
ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult
```

注意 eBPF 数据事件可能会无序到达，或者丢失事件，因此数据缓冲区中的数据可能缺少数据块，参数 streamBuffer 中通过
`streamBuffer.Head`
函数获取到目前为止已接收到的缓冲区前面的所有连续数据。因此，此时 **无法保证数据有效或缓冲区与数据包的开头对齐**。

如果返回 `ParseResult` 中的 `state` 为
`success`，且那么 kyanos 会自动删除掉 `ParseResult.ReadBytes` 个字节的数据；如果返回 `invalid`，那么通过
`FindBoundary` 找到下一个可能的 `Message` 边界；如果返回
`needsMoreData`，则不会删除数据，而是稍后重试。

### FindBoundary 寻找 Message 边界

FindBoundary 寻找 Message 边界，然后从解析失败状态中恢复。

```go
FindBoundary(streamBuffer *buffer.StreamBuffer, messageType MessageType, startPos int) int
```

conntrack.go 在一个循环中调用 ParseStream 和 FindBoundary，如果 ParseStream 返回 invalid，说明解析遇到了问题，接着会调用 FindBoundary 找到下一个位置，这个位置一般是 Message 的开头。如果请求带有一个 tag 比如 request
id，那么响应带有相同 request id 的可能性非常高。

### Match (Messages -> reqresp -> record)

ParseStream 解析成功的 Message 会放到对应的 ReqQueue 和 RespQueue 中，然后再它们匹配在一起创建 Record，主要有两种匹配方法：基于顺序 和 基于标签。

HTTP 等协议使用顺序匹配，而 Kafka 等协议使用基于标签的匹配。

Note: 如果是使用顺序匹配，可以直接使用 `matchByTimestamp`。

### Full Body Parsing 解析整个消息

目前，Full Body
Parsing 是 Match 的一部分。对于大多数协议，我们如果需要解析整个消息体，只有在请求响应匹配之后才可以，比如 Kafka 需要知道请求的 opcode，然后才可以根据 opcode 解析响应。

## Step.3-实现协议推断

在将内核数据抓取到用户态解析之前，我们需要识别出这个流量是什么协议的流量，当连接开启上面有数据传输时，kyanos 会基于一些规则判断该流量术语哪种协议，每个协议有自己的规则，HTTP 协议如下：

```c
static __always_inline enum message_type_t is_http_protocol(const char *old_buf, size_t count) {
  if (count < 5) {
    return 0;
  }
  char buf[4] = {};
  bpf_probe_read_user(buf, 4, old_buf);
  if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
    return kResponse;
  }
  if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
    return kRequest;
  }
  if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D') {
    return kRequest;
  }
  if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') {
    return kRequest;
  }
  return kUnknown;
}
```

Warn:

1. 新协议的规则可能会导致误报或漏报，导致影响其他协议的准确性。
2. 规则的顺序很重要。

出于这些原因，你需要注意以下几个事情：

1. 避免在协议中使用过于通用和常见的模式作为推理规则。例如，根据单独的 `0x00` 或
   `0x01` 的字节判断就不够严格。
2. 将更严格、更健壮的规则（例如 HTTP）放在前面。

## Step.4-添加命令行子命令并且实现过滤逻辑

需要添加到 watch 和 stat 命令下，增加需要的协议特定的过滤选项。

然后实现 `protocol.ProtocolFilter`：

```go
type ProtocolFilter interface {
	Filter(req ParsedMessage, resp ParsedMessage) bool
	FilterByProtocol(bpf.AgentTrafficProtocolT) bool
	FilterByRequest() bool
	FilterByResponse() bool
}
```

| 方法名             | 作用                       |
| ------------------ | -------------------------- |
| `Filter`           | 过滤请求和响应。           |
| `FilterByProtocol` | 是否根据协议类型进行过滤。 |
| `FilterByRequest`  | 是否根据请求进行过滤。     |
| `FilterByResponse` | 是否根据响应进行过滤。     |

## Step.5-注册协议解析器

在你写的模块下增加 init 函数，将其写入到 `ParsersMap` 里，例如：

```go
func init() {
	ParsersMap[bpf.AgentTrafficProtocolTKProtocolHTTP] = func() ProtocolStreamParser {
		return &HTTPStreamParser{}
	}
}
```

## Step.6-添加 e2e 测试

在 testdata 目录下添加对应协议的 e2e 测试，可以参考其他协议的写法（比如 `test_redis.sh` 等）。

## 其他

### 调试建议

打印协议解析日志建议使用
`common.ProtocolParserLog`. 打开 protocol 解析日志：`--protocol-log-level 5`
设置协议解析相关 log 日志为 debug 级别。

协议解析框架代码在 conntrack.go 的 `addDataToBufferAndTryParse` 函数里。

### 协议解析持久化信息

在某些协议中，如果需要在解析过程中保留一些数据（比如 kafka 中，它存储了请求缓冲区上看到的所有 correlation_id 的集合，而 FindBoundary 只返回 respStreamBuffer 上之前看到 correlation_id 的位置。）可以在协议的 Parser 里自定义一些变量保存（即 Parser 可以是有状态的），**kyanos 会为每个连接开启时创建独立的 Parser 并保持到连接关闭**。

## 总结

恭喜你成功向 Kyanos 添加新协议！由于你的贡献，新的协议解析器将使许多其他人受益！
