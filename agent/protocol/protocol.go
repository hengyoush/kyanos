package protocol

import (
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/bpf"
)

var ParsersMap map[bpf.AgentTrafficProtocolT]ProtocolStreamParser = make(map[bpf.AgentTrafficProtocolT]ProtocolStreamParser)

func GetParserByProtocol(protocol bpf.AgentTrafficProtocolT) ProtocolStreamParser {
	parser, ok := ParsersMap[protocol]
	if ok {
		return parser
	}
	return nil
}

type Record struct {
	req  ParsedMessage
	resp ParsedMessage
}

func NewRecord(req ParsedMessage, resp ParsedMessage) *Record {
	return &Record{
		req:  req,
		resp: resp,
	}
}

func (r *Record) Request() ParsedMessage {
	return r.req
}
func (r *Record) Response() ParsedMessage {
	return r.resp
}

type ProtocolStreamParser interface {
	ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult
	FindBoundary(streamBuffer *buffer.StreamBuffer, messageType MessageType, startPos int) int
	Match(reqStream *[]ParsedMessage, respStream *[]ParsedMessage) []Record
}

type ParsedMessage interface {
	FormatToString() string
	TimestampNs() uint64
	ByteSize() int
	IsReq() bool
	Seq() uint64
}

type ParseState int
type MessageType int

const (
	Request MessageType = iota
	Response
)

const (
	Invalid ParseState = iota
	NeedsMoreData
	Success
)

type ParseResult struct {
	ParsedMessages []ParsedMessage
	ParseState     ParseState
	ReadBytes      int
}

type FrameBase struct {
	timestampNs uint64
	byteSize    int
	seq         uint64
}

func NewFrameBase(timestampNs uint64, byteSize int, seq uint64) FrameBase {
	return FrameBase{timestampNs: timestampNs, byteSize: byteSize, seq: seq}
}

func (f *FrameBase) TimestampNs() uint64 {
	return f.timestampNs
}

func (f *FrameBase) ByteSize() int {
	return f.byteSize
}

func (f *FrameBase) Seq() uint64 {
	return f.seq
}

func (f *FrameBase) String() string {
	return fmt.Sprintf("timestamp_ns=%d byte_size=%d", f.timestampNs, f.byteSize)
}

type ProtocolFilter interface {
	Filter(req ParsedMessage, resp ParsedMessage) bool
	FilterByProtocol(bpf.AgentTrafficProtocolT) bool
	FilterByRequest() bool
	FilterByResponse() bool
}
