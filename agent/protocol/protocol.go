package protocol

import "eapm-ebpf/bpf"

type ProtocolType uint32

type ProtocolParser interface {
	Parse(*bpf.SyscallEvent, []byte) *BaseProtocolMessage
	FormatData([]byte) string
}

func GetProtocolParser(ProtocolType) ProtocolParser {
	return &StringParser{}
}

type BaseProtocolMessage struct {
	Parser       ProtocolParser
	Timestamp    uint64
	isTruncated  bool
	timedetails0 map[uint8]uint64
	timedetails1 map[uint8]uint64
	formatString string
	buf          []byte
}

func (s *BaseProtocolMessage) Ts() uint64 {
	return s.Timestamp
}

func (s *BaseProtocolMessage) IsTruncated() bool {
	return s.isTruncated
}

func (s *BaseProtocolMessage) FormatString() string {
	if s.formatString != "" {
		return s.formatString
	}
	s.formatString = s.Parser.FormatData(s.buf)
	return s.formatString
}

func (s *BaseProtocolMessage) AppendData(data []byte) {
	if !s.isTruncated {
		s.buf = append(s.buf, data...)
	}
}

func (s *BaseProtocolMessage) AddTimeDetail(step bpf.AgentStepT, ns uint64) {
	start, ok := s.timedetails0[uint8(step)]
	if !ok || start > ns {
		s.timedetails0[uint8(step)] = ns
	}
	end, ok := s.timedetails1[uint8(step)]
	if !ok || end < ns {
		s.timedetails1[uint8(step)] = ns
	}
}

type Record struct {
	Request  *BaseProtocolMessage
	Response *BaseProtocolMessage
	Start    uint64
	End      uint64
	Duration uint64
}
