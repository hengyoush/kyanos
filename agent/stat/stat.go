package stat

import (
	"fmt"
	"kyanos/agent/conn"
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"
	. "kyanos/common"

	"github.com/jefurry/logrus"
)

var log *logrus.Logger = common.Log

type StatRecorder struct {
	recordMap map[uint64]*StatRecord
}

func InitStatRecorder() *StatRecorder {
	sr := new(StatRecorder)
	sr.recordMap = make(map[uint64]*StatRecord)
	return sr
}

// 每个conn要有一些统计，简单先统计avg
type StatRecord struct {
	avg   float64
	total uint64
	count uint64
	max   uint64
}
type AnnotatedRecord struct {
	ConnDesc
	protocol.Record
	startTs                      uint64
	endTs                        uint64
	reqSize                      int
	respSize                     int
	totalDuration                int
	blackBoxDuration             int
	readFromSocketBufferDuration int
	reqSyscallEventDetails       []SyscallEventDetail
	respSyscallEventDetails      []SyscallEventDetail
	reqNicEventDetails           []NicEventDetail
	respNicEventDetails          []NicEventDetail
}

func CreateAnnotedRecord() *AnnotatedRecord {
	return &AnnotatedRecord{
		startTs:                      0,
		endTs:                        0,
		reqSize:                      -1,
		respSize:                     -1,
		totalDuration:                -1,
		blackBoxDuration:             -1,
		readFromSocketBufferDuration: -1,
		reqSyscallEventDetails:       make([]SyscallEventDetail, 0),
		respSyscallEventDetails:      make([]SyscallEventDetail, 0),
		reqNicEventDetails:           make([]NicEventDetail, 0),
		respNicEventDetails:          make([]NicEventDetail, 0),
	}
}

type AnnotatedRecordToStringOptions struct {
	recordMaxDumpBytes int
	nano               bool
}

func (r *AnnotatedRecord) String(options AnnotatedRecordToStringOptions) string {
	nano := options.nano
	firstPart := fmt.Sprintf("req: %s\n\nresp:%s\n\n%s\n[total duration] = %d(%s)(start=%s, end=%s)\n",
		r.Request().FormatToString(), r.Response().FormatToString(),
		(&r.ConnDesc).String(),
		common.ConvertDurationToMillisecondsIfNeeded(int64(r.totalDuration), nano), timeUnitName(nano),
		common.FormatTimestampWithPrecision(r.startTs, nano),
		common.FormatTimestampWithPrecision(r.endTs, nano))

	secondPart := fmt.Sprintf("[%s]=%d(%s) [copy from sockbuf]=%d(%s)\n", r.blackboxName(),
		common.ConvertDurationToMillisecondsIfNeeded(int64(r.blackBoxDuration), nano),
		timeUnitName(nano),
		common.ConvertDurationToMillisecondsIfNeeded(int64(r.readFromSocketBufferDuration), nano),
		timeUnitName(nano))
	thirdPart := fmt.Sprintf("[syscall] [%s count]=%d [%s count]=%d\n", r.syscallDisplayName(true), len(r.reqSyscallEventDetails),
		r.syscallDisplayName(false), len(r.respSyscallEventDetails))
	return firstPart + secondPart + thirdPart
}

func timeUnitName(nano bool) string {
	if nano {
		return "ns"
	} else {
		return "ms"
	}
}

func (r *AnnotatedRecord) blackboxName() string {
	if r.ConnDesc.Side == ServerSide {
		return "process internal duration"
	} else {
		return "network duration"
	}
}

func (r *AnnotatedRecord) syscallDisplayName(isReq bool) string {
	if isReq {
		if r.ConnDesc.Side == ServerSide {
			return "read"
		} else {
			return "write"
		}
	} else {
		if r.ConnDesc.Side == ServerSide {
			return "write"
		} else {
			return "read"
		}
	}
}

type SyscallEventDetail PacketEventDetail
type NicEventDetail PacketEventDetail
type PacketEventDetail struct {
	byteSize  int
	timestamp uint64
}

func (s *StatRecorder) ReceiveRecord(r protocol.Record, connection *conn.Connection4) error {
	streamEvents := connection.StreamEvents
	annotatedRecord := CreateAnnotedRecord()
	annotatedRecord.Record = r
	annotatedRecord.ConnDesc = ConnDesc{
		RemotePort: Port(connection.RemotePort),
		RemoteAddr: connection.RemoteIp,
		LocalAddr:  connection.LocalIp,
		LocalPort:  Port(connection.LocalPort),
		Protocol:   connection.Protocol,
		Pid:        uint32(connection.TgidFd >> 32),
		Side:       SideEnum(connection.IsServerSide()),
	}

	var writeSyscallEvents, readSyscallEvents, devOutSyscallEvents, nicIngressEvents, userCopyEvents, tcpInEvents []conn.KernEvent
	egressMessage := getParsedMessageBySide(r, connection.IsServerSide(), bpf.AgentTrafficDirectionTKEgress)
	ingressMessage := getParsedMessageBySide(r, connection.IsServerSide(), bpf.AgentTrafficDirectionTKIngress)
	writeSyscallEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTSYSCALL_OUT, egressMessage.Seq(), egressMessage.ByteSize())
	readSyscallEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTSYSCALL_IN, ingressMessage.Seq(), ingressMessage.ByteSize())
	devOutSyscallEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTDEV_OUT, egressMessage.Seq(), egressMessage.ByteSize())
	nicIngressEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTNIC_IN, ingressMessage.Seq(), ingressMessage.ByteSize())
	userCopyEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTUSER_COPY, ingressMessage.Seq(), ingressMessage.ByteSize())
	tcpInEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTTCP_IN, ingressMessage.Seq(), ingressMessage.ByteSize())

	hasNicInEvents := len(nicIngressEvents) > 0
	hasDevOutEvents := len(devOutSyscallEvents) > 0
	hasReadSyscallEvents := len(readSyscallEvents) > 0
	hasWriteSyscallEvents := len(writeSyscallEvents) > 0
	hasUserCopyEvents := len(userCopyEvents) > 0
	hasTcpInEvents := len(tcpInEvents) > 0
	if connection.IsServerSide() {
		if hasNicInEvents {
			annotatedRecord.startTs = nicIngressEvents[0].GetTimestamp()
		}
		if hasDevOutEvents {
			annotatedRecord.endTs = devOutSyscallEvents[len(devOutSyscallEvents)-1].GetTimestamp()
		}
		annotatedRecord.reqSize = ingressMessage.ByteSize()
		annotatedRecord.respSize = egressMessage.ByteSize()
		if hasNicInEvents && hasDevOutEvents {
			annotatedRecord.totalDuration = int(annotatedRecord.endTs) - int(annotatedRecord.startTs)
		}
		if hasReadSyscallEvents && hasWriteSyscallEvents {
			annotatedRecord.blackBoxDuration = int(writeSyscallEvents[len(writeSyscallEvents)-1].GetTimestamp()) - int(readSyscallEvents[0].GetTimestamp())
		}
		if hasUserCopyEvents && hasTcpInEvents {
			annotatedRecord.readFromSocketBufferDuration = int(userCopyEvents[len(userCopyEvents)-1].GetTimestamp()) - int(tcpInEvents[0].GetTimestamp())
		}
		annotatedRecord.reqSyscallEventDetails = KernEventsToEventDetails[SyscallEventDetail](readSyscallEvents)
		annotatedRecord.respSyscallEventDetails = KernEventsToEventDetails[SyscallEventDetail](writeSyscallEvents)
		annotatedRecord.reqNicEventDetails = KernEventsToEventDetails[NicEventDetail](nicIngressEvents)
		annotatedRecord.respNicEventDetails = KernEventsToEventDetails[NicEventDetail](devOutSyscallEvents)
	} else {
		if hasWriteSyscallEvents {
			annotatedRecord.startTs = writeSyscallEvents[0].GetTimestamp()
		}
		if hasReadSyscallEvents {
			annotatedRecord.endTs = readSyscallEvents[len(readSyscallEvents)-1].GetTimestamp()
		}
		annotatedRecord.reqSize = egressMessage.ByteSize()
		annotatedRecord.respSize = ingressMessage.ByteSize()
		if hasReadSyscallEvents && hasWriteSyscallEvents {
			annotatedRecord.totalDuration = int(annotatedRecord.endTs) - int(annotatedRecord.startTs)
		}
		if hasNicInEvents && hasDevOutEvents {
			annotatedRecord.blackBoxDuration = int(nicIngressEvents[len(nicIngressEvents)-1].GetTimestamp()) - int(devOutSyscallEvents[0].GetTimestamp())
		}
		if hasUserCopyEvents && hasTcpInEvents {
			annotatedRecord.readFromSocketBufferDuration = int(userCopyEvents[len(userCopyEvents)-1].GetTimestamp()) - int(tcpInEvents[0].GetTimestamp())
		}
		annotatedRecord.reqSyscallEventDetails = KernEventsToEventDetails[SyscallEventDetail](writeSyscallEvents)
		annotatedRecord.respSyscallEventDetails = KernEventsToEventDetails[SyscallEventDetail](readSyscallEvents)
		annotatedRecord.reqNicEventDetails = KernEventsToEventDetails[NicEventDetail](devOutSyscallEvents)
		annotatedRecord.respNicEventDetails = KernEventsToEventDetails[NicEventDetail](nicIngressEvents)
	}
	log.Infoln(annotatedRecord.String(AnnotatedRecordToStringOptions{
		nano: false,
	}))
	return nil
}

func KernEventsToEventDetails[k PacketEventDetail | SyscallEventDetail | NicEventDetail](kernEvents []conn.KernEvent) []k {
	if len(kernEvents) == 0 {
		return []k{}
	}
	result := make([]k, 0)
	for _, each := range kernEvents {
		result = append(result, k{
			byteSize:  each.GetLen(),
			timestamp: each.GetTimestamp(),
		})
	}
	return result
}

func getParsedMessageBySide(r protocol.Record, IsServerSide bool, direct bpf.AgentTrafficDirectionT) protocol.ParsedMessage {
	if !IsServerSide {
		if direct == bpf.AgentTrafficDirectionTKEgress {
			return r.Request()
		} else {
			return r.Response()
		}
	} else {
		if direct == bpf.AgentTrafficDirectionTKEgress {
			return r.Response()
		} else {
			return r.Request()
		}
	}
}
func (s *StatRecorder) RemoveRecord(tgidFd uint64) {
	delete(s.recordMap, tgidFd)
}
