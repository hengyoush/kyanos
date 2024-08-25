package protocol

import (
	"fmt"
	"kyanos/bpf"
	"kyanos/common"

	"github.com/jefurry/logrus"
)

var log *logrus.Logger = common.Log

type ProtocolType uint32

type BaseProtocolMessage struct {
	IsReq        bool
	IsServerSide bool
	StartTs      uint64
	EndTs        uint64
	isTruncated  bool
	timedetails0 map[uint8]uint64
	timedetails1 map[uint8]uint64
	rawString    string
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
	return msg
}

func InitProtocolMessageWithEvent(evt *bpf.SyscallEventData, isReq bool, isServerSide bool) *BaseProtocolMessage {
	msg := new(BaseProtocolMessage)
	msg.StartTs = evt.SyscallEvent.Ke.Ts
	msg.EndTs = evt.SyscallEvent.Ke.Ts
	msg.isTruncated = evt.SyscallEvent.BufSize != uint32(len(evt.Buf))
	msg.buf = append(msg.buf, evt.Buf...)
	msg.timedetails0 = make(map[uint8]uint64)
	msg.timedetails1 = make(map[uint8]uint64)
	msg.IsReq = isReq
	msg.IsServerSide = isServerSide
	return msg
}

// func (s *BaseProtocolMessage) StartTs() uint64 {
// 	return s.startTs
// }

func (s *BaseProtocolMessage) IsTruncated() bool {
	return s.isTruncated
}

func (s *BaseProtocolMessage) FormatRawBufToString() string {
	if s.rawString != "" {
		return s.rawString
	}
	s.rawString = string(s.buf)
	return s.rawString
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

		if s.IsReq {
			result += fmt.Sprintf("total bytes: %d, duration: %dns, syscall count: %d\n", s.totalBytes, s.EndTs-s.StartTs, s.syscallCnt)
		} else {
			result += fmt.Sprintf("total bytes: %d, duration: %dns, syscall count: %d\n", s.totalBytes, s.EndTs-s.StartTs, s.syscallCnt)
		}
	} else {
		// req: NICIN => SyscallIn
		for i := bpf.AgentStepTNIC_IN; i < bpf.AgentStepTEnd; i++ {
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
		lastStep = bpf.AgentStepTEnd
		// resp: SyscallOut => NICOUT
		for i := bpf.AgentStepTStart + 1; i <= bpf.AgentStepTNIC_OUT; i++ {
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
		result += fmt.Sprintf("total bytes: %d, duration: %dns, syscall count: %d\n", s.totalBytes, s.EndTs-s.StartTs, s.syscallCnt)
	}

	return result
}

func (req *BaseProtocolMessage) ExportReqRespTimeDetails(resp *BaseProtocolMessage) string {
	if req.IsServerSide {
		start, ok := req.timedetails1[uint8(bpf.AgentStepTSYSCALL_IN)]
		if !ok {
			log.Debugln("[no info] no syscall in time detail")
			return ""
		}
		end, ok := resp.timedetails0[uint8(bpf.AgentStepTSYSCALL_OUT)]
		if !ok {
			log.Debugln("[no info] no syscall out time detail")
			return ""
		}
		return fmt.Sprintf("[服务耗时]dur=%d(ns)\n", end-start)
	} else {
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
}

func (s *BaseProtocolMessage) AppendData(data []byte) {
	if !s.isTruncated {
		s.buf = append(s.buf, data...)
	}
}

func (s *BaseProtocolMessage) AddTimeDetail(step bpf.AgentStepT, ns uint64) {
	// ns += common.LaunchEpochTime
	start, ok := s.timedetails0[uint8(step)]
	if !ok || start > ns {
		s.timedetails0[uint8(step)] = ns
	}
	end, ok := s.timedetails1[uint8(step)]
	if !ok || end < ns {
		s.timedetails1[uint8(step)] = ns
	}
	if s.StartTs > ns {
		s.StartTs = ns
	}
	if s.EndTs < ns {
		s.EndTs = ns
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

func (s *BaseProtocolMessage) IncrSyscallCount() {
	s.syscallCnt++
}

func (s *BaseProtocolMessage) IncrTotalBytesBy(bytes uint) {
	s.totalBytes += bytes
}

func (s *BaseProtocolMessage) Data() []byte {
	return s.buf
}

type Record struct {
	Request  *BaseProtocolMessage
	Response *BaseProtocolMessage
	Start    uint64
	End      uint64
	Duration uint64
}