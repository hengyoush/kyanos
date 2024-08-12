package protocol

import (
	"eapm-ebpf/bpf"
	"eapm-ebpf/common"
	"fmt"

	"github.com/jefurry/logrus"
)

var log *logrus.Logger = common.Log

type ProtocolType uint32

type ProtocolParser interface {
	Parse(*bpf.SyscallEvent, []byte, bool, bool) *BaseProtocolMessage
	FormatData([]byte) string
}

func GetProtocolParser(ProtocolType) ProtocolParser {
	return &StringParser{}
}

type BaseProtocolMessage struct {
	Parser       ProtocolParser
	IsReq        bool
	IsServerSide bool
	Timestamp    uint64
	isTruncated  bool
	timedetails0 map[uint8]uint64
	timedetails1 map[uint8]uint64
	formatString string
	buf          []byte
	syscallCnt   uint
	duration     uint // 读/写总用时
	totalBytes   uint // 读/写总字节数
}

func InitProtocolMessage(isReq bool, isServerSide bool) *BaseProtocolMessage {
	msg := new(BaseProtocolMessage)
	msg.IsReq = isReq
	msg.IsServerSide = isServerSide
	msg.timedetails0 = make(map[uint8]uint64)
	msg.timedetails1 = make(map[uint8]uint64)
	msg.buf = make([]byte, 0)
	msg.Parser = &StringParser{}
	return msg
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

func (s *BaseProtocolMessage) ExportTimeDetails() string {

	var result string
	lastStep := bpf.AgentStepTEnd
	if !s.IsServerSide {
		// req:  SyscallOut => NICOUT
		// resp: NICIN => SyscallIn
		for i := bpf.AgentStepTStart + 1; i < bpf.AgentStepTEnd; i++ {
			start := s.timedetails0[uint8(i)]
			end := s.timedetails1[uint8(i)]
			if start != 0 && end != 0 {
				if lastStep != bpf.AgentStepTEnd {
					lastDuration := end - s.timedetails0[uint8(lastStep)]
					result += fmt.Sprintf("[%s => %s] dur=%dns(%d-%d), cur=%d(ns)\n", common.StepCNNames[lastStep], common.StepCNNames[i], lastDuration, end, s.timedetails0[uint8(lastStep)], end-start)
				} else {
					result += fmt.Sprintf("[%s]dur= %d(ns)\n", common.StepCNNames[i], end-start)
				}
				lastStep = i
			}
		}
	} else {
		// req: NICIN => SyscallIn
		// resp: SyscallOut => NICOUT
		for i := bpf.AgentStepTNIC_IN; i < bpf.AgentStepTEnd; i++ {
			start := s.timedetails0[uint8(i)]
			end := s.timedetails1[uint8(i)]
			if start != 0 && end != 0 {
				result += fmt.Sprintf("[%s]dur= %d(ns)\n", common.StepCNNames[i], end-start)
			}
		}
		for i := bpf.AgentStepTStart + 1; i <= bpf.AgentStepTNIC_OUT; i++ {
			start := s.timedetails0[uint8(i)]
			end := s.timedetails1[uint8(i)]
			if start != 0 && end != 0 {
				result += fmt.Sprintf("[%s]dur= %d(ns)\n", common.StepCNNames[i], end-start)
			}
		}
	}

	return result
}

func (req *BaseProtocolMessage) ExportReqRespTimeDetails(resp *BaseProtocolMessage) string {
	start, ok := req.timedetails1[uint8(bpf.AgentStepTDEV_OUT)]
	if !ok {
		log.Debugln("[no info] no dev out time detail")
		return ""
	}
	end, ok := resp.timedetails0[uint8(bpf.AgentStepTNIC_IN)]
	if !ok {
		log.Debugln("[no info] no nic in time detail")
		return ""
	}
	return fmt.Sprintf("[网络耗时]dur=%d(ns)\n", end-start)
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

func (s *BaseProtocolMessage) HasData() bool {
	return len(s.buf) > 0
}

func (s *BaseProtocolMessage) HasEvent() bool {
	return len(s.timedetails0) > 0 || len(s.timedetails1) > 0
}

func (s *BaseProtocolMessage) CopyTimeDetailFrom(t *BaseProtocolMessage) {
	s.timedetails0 = t.timedetails0
	s.timedetails1 = t.timedetails1
}

type Record struct {
	Request  *BaseProtocolMessage
	Response *BaseProtocolMessage
	Start    uint64
	End      uint64
	Duration uint64
}
