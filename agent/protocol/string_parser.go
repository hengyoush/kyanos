package protocol

import (
	"eapm-ebpf/bpf"
	"eapm-ebpf/common"
)

type StringParser struct {
}

func (h *StringParser) Parse(evt *bpf.SyscallEvent, buf []byte, isReq bool, isServerSide bool) *BaseProtocolMessage {
	msg := new(BaseProtocolMessage)
	msg.Timestamp = evt.Ke.Ts + common.LaunchEpochTime
	msg.isTruncated = evt.BufSize != uint32(len(buf))
	msg.buf = append(msg.buf, buf...)
	msg.Parser = h
	msg.timedetails0 = make(map[uint8]uint64)
	msg.timedetails1 = make(map[uint8]uint64)
	msg.IsReq = isReq
	msg.IsServerSide = isServerSide
	return msg
}

func (h *StringParser) FormatData(data []byte) string {
	return string(data)
}
