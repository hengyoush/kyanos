package protocol

import (
	"eapm-ebpf/bpf"
	"eapm-ebpf/common"
)

type StringParser struct {
}

func (h *StringParser) Parse(evt *bpf.SyscallEvent, buf []byte) *BaseProtocolMessage {
	msg := new(BaseProtocolMessage)
	msg.Timestamp = evt.Ke.Ts + common.LaunchEpochTime
	msg.isTruncated = evt.BufSize != uint32(len(buf))
	msg.buf = append(msg.buf, buf...)
	msg.Parser = h
	return msg
}

func (h *StringParser) FormatData(data []byte) string {
	return string(data)
}
