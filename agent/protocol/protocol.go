package protocol

import (
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/bpf"
	"kyanos/common"
)

type ProtocolCreator func() ProtocolStreamParser

type StreamId int64

type ParsedMessageQueue []ParsedMessage

var ParsersMap map[bpf.AgentTrafficProtocolT]ProtocolCreator = make(map[bpf.AgentTrafficProtocolT]ProtocolCreator)

func GetParserByProtocol(protocol bpf.AgentTrafficProtocolT) ProtocolStreamParser {
	parserCreator, ok := ParsersMap[protocol]
	if ok {
		return parserCreator()
	}
	return nil
}

type Record struct {
	Req            ParsedMessage
	Resp           ParsedMessage
	ResponseStatus ResponseStatus
}

func NewRecord(req ParsedMessage, resp ParsedMessage) *Record {
	return &Record{
		Req:  req,
		Resp: resp,
	}
}

func (r *Record) Request() ParsedMessage {
	return r.Req
}
func (r *Record) Response() ParsedMessage {
	return r.Resp
}

type RecordToStringOptions struct {
	RecordMaxDumpBytes int
	IncludeReqBody     bool
	IncludeRespBody    bool
}

func (r *Record) String(opt RecordToStringOptions) string {
	var result string
	if opt.IncludeReqBody {
		result += fmt.Sprintf("[ Request ]\n%s\n\n", common.TruncateString(r.Req.FormatToString(), opt.RecordMaxDumpBytes))
	}
	if opt.IncludeRespBody {
		result += fmt.Sprintf("[ Response ]\n%s\n\n", common.TruncateString(r.Resp.FormatToString(), opt.RecordMaxDumpBytes))
	}
	return result
}

type ProtocolStreamParser interface {
	ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult
	FindBoundary(streamBuffer *buffer.StreamBuffer, messageType MessageType, startPos int) int
	Match(reqStreams map[StreamId]*ParsedMessageQueue, respStreams map[StreamId]*ParsedMessageQueue) []Record
}

type ParsedMessage interface {
	FormatToString() string
	TimestampNs() uint64
	ByteSize() uint32
	IsReq() bool
	Seq() uint32
	StreamId() StreamId
}

type ParseState int
type MessageType int

const (
	Request MessageType = iota
	Response
	Unknown
)

func (m MessageType) String() string {
	switch m {
	case Request:
		return "Request"
	case Response:
		return "Response"
	default:
		return "Unknwon"
	}
}

const (
	Invalid ParseState = iota
	NeedsMoreData
	Success
	Ignore
)

type ParseResult struct {
	ParseState     ParseState
	ParsedMessages []ParsedMessage
	ReadBytes      uint32
}

type FrameBase struct {
	timestampNs uint64
	byteSize    uint32
	seq         uint32
}

func NewFrameBase(timestampNs uint64, byteSize uint32, seq uint32) FrameBase {
	return FrameBase{timestampNs: timestampNs, byteSize: byteSize, seq: seq}
}

func (f *FrameBase) SetTimeStamp(t uint64) {
	f.timestampNs = t
}

func (f *FrameBase) TimestampNs() uint64 {
	return f.timestampNs
}

func (f *FrameBase) ByteSize() uint32 {
	return f.byteSize
}
func (f *FrameBase) IncrByteSize(incr uint32) {
	f.byteSize += uint32(incr)
}

func (f *FrameBase) Seq() uint32 {
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

type StatusfulMessage interface {
	Status() ResponseStatus
}
type ResponseStatus int8

const (
	NoneStatus ResponseStatus = iota
	SuccessStatus
	FailStatus
	UnknownStatus
)
