# How to Contribute a New Protocol to Kyanos

## Background

Kyanos needs to capture protocol messages to form request-response pairs for terminal display. Therefore, Kyanos requires protocol parsing code for each protocol. Currently, it supports HTTP, MySQL, and Redis, and will support more in the future. This document will explain the overall architecture of Kyanos protocol parsing to assist in developing new protocols.

## Overview of Protocol Parsing Process

![kyanos protocol parse flow](/protocol-parse-flow.png)

Starting from the left, Kyanos instruments system calls like read and write to capture the data read and written by the application process and sends it to user space through the perf event buffer.

In user space, the data is placed into reqStreamBuffer or respStreamBuffer based on whether the connection is client-side or server-side and data's direction. This data is purely application protocol data without tcp/ip protocol headers.

Kyanos uses the corresponding protocol parser to parse the data placed in the streamBuffer, then associates the parsed requests and responses, and finally performs Full Body parsing as needed by the protocol to generate a "record".

## Some Terminology

Message: The most basic data unit of a protocol, usually consisting of a header and a body.

Request / Response: A request or response consists of one or more Messages sent together, representing a message. (*Note: For simple protocols like HTTP1.1, a Request/Response may correspond to a single Message, but for complex protocols like MySQL, multiple Messages together correspond to a Request/Response*)

Record: A Record represents a completed request-response pair.

## Step.0-Preparation

We need to do the following:

1. Implement user-space protocol parsing
   1. Define protocol message types (i.e., the structure of requests and responses)
   2. Implement a `Parser`, specifically the `ProtocolStreamParser` interface, which implements the specific logic for protocol parsing and request-response matching.
2. Implement kernel-space protocol inference logic.
3. Add command-line subcommands to implement filtering logic.
4. Add e2e tests.

## Step.1-Define Protocol Message Types

Create a new directory under /agent/protocol, named after the protocol, for example: kafka.

### Define Message

Generally, the protocol you want to implement will have a common Header, which contains some metadata, such as a flag indicating whether it is a request or a response. You need to store this information in the fields of the Message you define, such as the MySQL protocol definition:

```go
type MysqlPacket struct {
	FrameBase
	seqId byte
	msg   string
	cmd   int
	isReq bool
}
```

Generally, both Message and the following Request/Response need to embed a `FrameBase` struct. `FrameBase` is defined as follows and contains some basic information:

```go
type FrameBase struct {
	timestampNs uint64
	byteSize    int
	seq         uint64
}
```

For simple protocols like HTTP, since a single Message corresponds to a request or response, there is no need for Full Body parsing, and therefore no need to define a Message. You can directly define Request and Response.

### Define Request and Response

Requests and responses are at a higher level than Messages and consist of one or more Messages. `struct Request` or `struct Response` should contain data specific to the request/response and should implement the ParsedMessage interface, defined as follows:

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

| Method Name           | Function                                                            |
|-----------------------|----------------------------------------------------------------------|
| `FormatToString()`    | Formats the message into a string representation.                    |
| `TimestampNs()`       | Returns the timestamp of the message (in nanoseconds).               |
| `ByteSize()`          | Returns the byte size of the message.                                |
| `IsReq()`             | Determines if the message is a request.                              |
| `Seq()`               | Returns the sequence number of the byte stream.(Obtain Seq from `streamBuffer.Head().LeftBoundary()`)                      |

Example for HTTP:
```go
type ParsedHttpRequest struct {
	FrameBase
	Path   string
	Host   string
	Method string

	buf []byte
}
```

> Note. In `protocol.BinaryDecoder`, the `BinaryDecoder` class provides some convenient utility functions for extracting characters, strings, or integers from the buffer. We should use these functions when implementing ParseFrame, FindFrameBoundary, and Full Body parsing below.

## Step.2-Implement Protocol Parsing

After defining the request and response types, you can start implementing the parsing process. Specifically, you need to implement the `ProtocolStreamParser` interface:

```go
type ProtocolStreamParser interface {
	ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult
	FindBoundary(streamBuffer *buffer.StreamBuffer, messageType MessageType, startPos int) int
	Match(reqStream *[]ParsedMessage, respStream *[]ParsedMessage) []Record
}
```

- ParseStream: Parse Message
- FindBoundary: Find Message boundary
- Match: ReqResp matching
- Full Body Parse (optional): Full Body parsing

### ParseStream (Buffer -> Message/ReqResp)

ParseStream parses the Message or directly parses the ReqResp from the network data.

```go
ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult
```

Note that eBPF data events may arrive out of order or lose events, so the data in the buffer may be missing chunks. The `streamBuffer` parameter provides all the continuous data received so far through the `streamBuffer.Head` function. Therefore, it is **not guaranteed that the data is valid or aligned with the beginning of the packet**.

If the `state` in the returned `ParseResult` is `success`, Kyanos will automatically delete the number of bytes specified by `ParseResult.ReadBytes`. If `invalid` is returned, the next possible `Message` boundary is found through `FindBoundary`. If `needsMoreData` is returned, the data is not deleted and will be retried later.

### FindBoundary - Find Message Boundary

FindBoundary finds the Message boundary and recovers from the parsing failure state.

```go
FindBoundary(streamBuffer *buffer.StreamBuffer, messageType MessageType, startPos int) int
```

In conntrack.go, ParseStream and FindBoundary are called in a loop until streamBuffer is empty. If ParseStream returns invalid, it indicates a parsing problem, and FindBoundary is called to find the next position, which is usually the beginning of the Message. If the request has a tag like request id, the response is very likely to have the same request id.

### Match (Messages -> reqresp -> record)

Messages successfully parsed by ParseStream are placed in the corresponding ReqQueue and RespQueue, and then matched together to create a Record. There are two main matching methods: order-based and tag-based.

Protocols like HTTP use order-based matching, while protocols like Kafka use tag-based matching.

Note: If using order-based matching, you can directly use `matchByTimestamp`.

### Full Body Parsing - Parse the Entire Message

Currently, Full Body Parsing is part of Match. For most protocols, if we need to parse the entire message body, it can only be done after the request-response matching, such as Kafka, which needs to know the request opcode before parsing the response based on the opcode.

## Step.3-Implement Protocol Inference

Before capturing kernel data to user space for parsing, we need to identify what protocol the traffic belongs to. When a connection is opened and data is transmitted, Kyanos will determine the protocol based on some rules. Each protocol has its own rules. For example, the HTTP protocol is as follows:
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

1. The rules of the new protocol may cause false positives or false negatives, affecting the accuracy of other protocols.
2. The order of the rules is important.

For these reasons, you need to pay attention to the following:

1. Avoid using overly general and common patterns as inference rules in the protocol. For example, judging based on a single byte like `0x00` or `0x01` is not strict enough.
2. Place stricter and more robust rules (such as HTTP) at the front.

## Step.4-Add Command-Line Subcommands and Implement Filtering Logic

Add the necessary protocol-specific filtering options to the watch and stat commands.

Then implement `protocol.ProtocolFilter`:

```go
type ProtocolFilter interface {
	Filter(req ParsedMessage, resp ParsedMessage) bool
	FilterByProtocol(bpf.AgentTrafficProtocolT) bool
	FilterByRequest() bool
	FilterByResponse() bool
}
```

| Method Name           | Function                                                            |
|-----------------------|----------------------------------------------------------------------|
| `Filter`              | Filters requests and responses.                                      |
| `FilterByProtocol`    | Filters based on protocol type.                                      |
| `FilterByRequest`     | Filters based on requests.                                           |
| `FilterByResponse`    | Filters based on responses.                                          |

## Step.5-Register Protocol Parser

Add an init function in your module to write it into the `ParsersMap`, for example:
```go
func init() {
	ParsersMap[bpf.AgentTrafficProtocolTKProtocolHTTP] = func() ProtocolStreamParser {
		return &HTTPStreamParser{}
	}
}
```

## Step.6-Add e2e Tests

Add e2e tests for the corresponding protocol in the testdata directory. You can refer to the implementation of other protocols (e.g., `test_redis.sh`).

## Others

### Debugging Suggestions

It is recommended to use `common.ProtocolParserLog` for printing protocol parsing logs. Enable protocol parsing logs with `--protocol-log-level 5` to set protocol parsing-related log levels to debug.

The protocol parsing framework code is in the `addDataToBufferAndTryParse` function in conntrack.go.

### Persisting Protocol Parsing Information

In some protocols, if you need to retain some data during the parsing process (e.g., in Kafka, it stores a set of all correlation_ids seen on the request buffer, and FindBoundary only returns the position of the previously seen correlation_id on the respStreamBuffer), you can customize some variables in the protocol's Parser to save them (i.e., the Parser can be stateful). **Kyanos will create a separate Parser for each connection when it is opened and keep it until the connection is closed**.

## Summary

Congratulations on successfully adding a new protocol to Kyanos! Your contribution will benefit many others with the new protocol parser!