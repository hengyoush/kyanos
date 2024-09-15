package analysis

import (
	"fmt"
	"kyanos/agent/conn"
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"
	. "kyanos/common"

	"github.com/jefurry/logrus"
)

var outputLog *logrus.Logger = logrus.New()

type StatRecorder struct {
}

func InitStatRecorder() *StatRecorder {
	sr := new(StatRecorder)
	return sr
}

type AnnotatedRecord struct {
	ConnDesc
	protocol.Record
	startTs                      uint64
	endTs                        uint64
	reqSize                      int
	respSize                     int
	totalDuration                float64
	blackBoxDuration             float64
	readFromSocketBufferDuration float64
	reqSyscallEventDetails       []SyscallEventDetail
	respSyscallEventDetails      []SyscallEventDetail
	reqNicEventDetails           []NicEventDetail
	respNicEventDetails          []NicEventDetail
}

func (a *AnnotatedRecord) GetTotalDurationMills() float64 {
	return common.NanoToMills(int32(a.totalDuration))
}

func (a *AnnotatedRecord) GetBlackBoxDurationMills() float64 {
	return common.NanoToMills(int32(a.blackBoxDuration))
}

func (a *AnnotatedRecord) GetReadFromSocketBufferDurationMills() float64 {
	return common.NanoToMills(int32(a.readFromSocketBufferDuration))
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
	Nano bool
	protocol.RecordToStringOptions
	MetricTypeSet
	IncludeSyscallStat bool
}

func (r *AnnotatedRecord) String(options AnnotatedRecordToStringOptions) string {
	nano := options.Nano
	var result string
	result += r.Record.String(options.RecordToStringOptions)
	result += "\n"
	if _, ok := options.MetricTypeSet[TotalDuration]; ok {
		result += fmt.Sprintf("[total duration] = %.3f(%s)(start=%s, end=%s)\n", common.ConvertDurationToMillisecondsIfNeeded(float64(r.totalDuration), nano), timeUnitName(nano),
			common.FormatTimestampWithPrecision(r.startTs, nano),
			common.FormatTimestampWithPrecision(r.endTs, nano))
	}
	if _, ok := options.MetricTypeSet[ReadFromSocketBufferDuration]; ok {
		result += fmt.Sprintf("[read from sockbuf]=%.3f(%s)\n", common.ConvertDurationToMillisecondsIfNeeded(float64(r.readFromSocketBufferDuration), nano),
			timeUnitName(nano))
	}
	if _, ok := options.MetricTypeSet[BlackBoxDuration]; ok {
		result += fmt.Sprintf("[%s]=%.3f(%s)\n", r.blackboxName(),
			common.ConvertDurationToMillisecondsIfNeeded(float64(r.blackBoxDuration), nano),
			timeUnitName(nano))
	}
	if _, ok := options.MetricTypeSet[RequestSize]; ok {
		result += fmt.Sprintf("[syscall] [%s count]=%d [%s bytes]=%d\n",
			r.syscallDisplayName(true), len(r.reqSyscallEventDetails),
			r.syscallDisplayName(true), r.reqSize)
	}
	if _, ok := options.MetricTypeSet[ResponseSize]; ok {
		result += fmt.Sprintf("[syscall] [%s count]=%d [%s bytes]=%d\n",
			r.syscallDisplayName(false), len(r.respSyscallEventDetails),
			r.syscallDisplayName(false), r.respSize)
	}
	if options.IncludeSyscallStat {
		result += fmt.Sprintf("[syscall] [%s count]=%d [%s bytes]=%d [%s count]=%d [%s bytes]=%d\n\n",
			r.syscallDisplayName(true), len(r.reqSyscallEventDetails),
			r.syscallDisplayName(true), r.reqSize,
			r.syscallDisplayName(false), len(r.respSyscallEventDetails),
			r.syscallDisplayName(false), r.respSize)
	}
	return result
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

func (s *StatRecorder) ReceiveRecord(r protocol.Record, connection *conn.Connection4, recordsChannel chan<- *AnnotatedRecord) error {
	streamEvents := connection.StreamEvents
	annotatedRecord := CreateAnnotedRecord()
	annotatedRecord.Record = r
	var side SideEnum = ClientSide
	if connection.IsServerSide() {
		side = ServerSide
	}
	annotatedRecord.ConnDesc = ConnDesc{
		RemotePort: Port(connection.RemotePort),
		RemoteAddr: connection.RemoteIp,
		LocalAddr:  connection.LocalIp,
		LocalPort:  Port(connection.LocalPort),
		Protocol:   uint32(connection.Protocol),
		Pid:        uint32(connection.TgidFd >> 32),
		Side:       side,
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
	if !hasNicInEvents {
		nicIngressEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTDEV_IN, ingressMessage.Seq(), ingressMessage.ByteSize())
		hasNicInEvents = len(nicIngressEvents) > 0
	}
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
			annotatedRecord.totalDuration = float64(annotatedRecord.endTs) - float64(annotatedRecord.startTs)
		}
		if hasReadSyscallEvents && hasWriteSyscallEvents {
			annotatedRecord.blackBoxDuration = float64(writeSyscallEvents[len(writeSyscallEvents)-1].GetTimestamp()) - float64(readSyscallEvents[0].GetTimestamp())
		} else {
			annotatedRecord.blackBoxDuration = float64(egressMessage.TimestampNs()) - float64(ingressMessage.TimestampNs())
		}
		if hasUserCopyEvents && hasTcpInEvents {
			annotatedRecord.readFromSocketBufferDuration = float64(userCopyEvents[len(userCopyEvents)-1].GetTimestamp()) - float64(tcpInEvents[0].GetTimestamp())
		}
		annotatedRecord.reqSyscallEventDetails = KernEventsToEventDetails[SyscallEventDetail](readSyscallEvents)
		annotatedRecord.respSyscallEventDetails = KernEventsToEventDetails[SyscallEventDetail](writeSyscallEvents)
		annotatedRecord.reqNicEventDetails = KernEventsToEventDetails[NicEventDetail](nicIngressEvents)
		annotatedRecord.respNicEventDetails = KernEventsToEventDetails[NicEventDetail](devOutSyscallEvents)
	} else {
		if hasWriteSyscallEvents {
			annotatedRecord.startTs = writeSyscallEvents[0].GetTimestamp()
		} else {
			annotatedRecord.startTs = egressMessage.TimestampNs()
		}
		if hasReadSyscallEvents {
			annotatedRecord.endTs = readSyscallEvents[len(readSyscallEvents)-1].GetTimestamp()
		} else {
			annotatedRecord.endTs = ingressMessage.TimestampNs()
		}
		annotatedRecord.reqSize = egressMessage.ByteSize()
		annotatedRecord.respSize = ingressMessage.ByteSize()
		if hasReadSyscallEvents && hasWriteSyscallEvents {
			annotatedRecord.totalDuration = float64(annotatedRecord.endTs) - float64(annotatedRecord.startTs)
		} else {
			annotatedRecord.totalDuration = float64(ingressMessage.TimestampNs()) - float64(egressMessage.TimestampNs())
		}
		if hasNicInEvents && hasDevOutEvents {
			annotatedRecord.blackBoxDuration = float64(nicIngressEvents[len(nicIngressEvents)-1].GetTimestamp()) - float64(devOutSyscallEvents[0].GetTimestamp())
		}
		if hasUserCopyEvents && hasTcpInEvents {
			annotatedRecord.readFromSocketBufferDuration = float64(userCopyEvents[len(userCopyEvents)-1].GetTimestamp()) - float64(tcpInEvents[0].GetTimestamp())
		}
		annotatedRecord.reqSyscallEventDetails = KernEventsToEventDetails[SyscallEventDetail](writeSyscallEvents)
		annotatedRecord.respSyscallEventDetails = KernEventsToEventDetails[SyscallEventDetail](readSyscallEvents)
		annotatedRecord.reqNicEventDetails = KernEventsToEventDetails[NicEventDetail](devOutSyscallEvents)
		annotatedRecord.respNicEventDetails = KernEventsToEventDetails[NicEventDetail](nicIngressEvents)
	}
	streamEvents.DiscardEventsBySeq(egressMessage.Seq()+uint64(egressMessage.ByteSize()), true)
	streamEvents.DiscardEventsBySeq(ingressMessage.Seq()+uint64(ingressMessage.ByteSize()), false)
	if recordsChannel == nil {
		outputLog.Infoln(annotatedRecord.String(AnnotatedRecordToStringOptions{
			Nano: false,
			MetricTypeSet: MetricTypeSet{
				ResponseSize:                 false,
				RequestSize:                  false,
				ReadFromSocketBufferDuration: true,
				BlackBoxDuration:             true,
				TotalDuration:                true,
			}, IncludeSyscallStat: true,
			RecordToStringOptions: protocol.RecordToStringOptions{
				IncludeReqBody:     true,
				IncludeRespBody:    true,
				RecordMaxDumpBytes: 1024,
			},
		}))
	} else {
		recordsChannel <- annotatedRecord
	}
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
}
