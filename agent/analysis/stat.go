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
	reqSslSize                   int
	respSslSize                  int
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

type events struct {
	sslWriteSyscallEvents                                []conn.SslEvent
	sslReadSyscallEvents                                 []conn.SslEvent
	writeSyscallEvents                                   []conn.KernEvent
	readSyscallEvents                                    []conn.KernEvent
	devOutEvents                                         []conn.KernEvent
	nicIngressEvents                                     []conn.KernEvent
	userCopyEvents                                       []conn.KernEvent
	tcpInEvents                                          []conn.KernEvent
	egressMessage                                        protocol.ParsedMessage
	ingressMessage                                       protocol.ParsedMessage
	ingressSeq, egressSeq, ingressKernSeq, egressKernSeq uint64
	ingressKernLen, egressKernLen                        int
}

func getKernSeqAndLen(syscallEvents []conn.SslEvent) (uint64, int) {
	var syscallSeq uint64
	var syscallLen int
	if len(syscallEvents) > 0 {
		for idx := 0; idx < len(syscallEvents); idx++ {
			each := syscallEvents[idx]
			if each.KernSeq != 0 {
				syscallSeq = each.KernSeq
				break
			}
		}
		if syscallSeq == 0 {
			return 0, 0
		}

		for idx := len(syscallEvents) - 1; idx >= 0; idx-- {
			each := syscallEvents[idx]
			if each.KernSeq != 0 {
				syscallLen = int(each.KernSeq - syscallSeq)
				break
			}
		}

		return syscallSeq, syscallLen
	}
	return 0, 0
}

func prepareEvents(r protocol.Record, connection *conn.Connection4) *events {
	streamEvents := connection.StreamEvents
	var events events
	var writeSyscallEvents, readSyscallEvents, devOutEvents, nicIngressEvents, userCopyEvents, tcpInEvents []conn.KernEvent
	var sslWriteSyscallEvents, sslReadSyscallEvents []conn.SslEvent
	var ingressSeq, egressSeq, ingressKernSeq, egressKernSeq uint64
	var ingressKernLen, egressKernLen int

	egressMessage := getParsedMessageBySide(r, connection.IsServerSide(), DirectEgress)
	ingressMessage := getParsedMessageBySide(r, connection.IsServerSide(), DirectIngress)
	ssl := connection.IsSsl()
	if ssl {
		ingressSeq = ingressMessage.Seq()
		egressSeq = egressMessage.Seq()
		sslWriteSyscallEvents = streamEvents.FindAndRemoveSslEventsBySeqAndLen(bpf.AgentStepTSSL_OUT, egressMessage.Seq(), egressMessage.ByteSize())
		sslReadSyscallEvents = streamEvents.FindAndRemoveSslEventsBySeqAndLen(bpf.AgentStepTSSL_IN, ingressMessage.Seq(), ingressMessage.ByteSize())

		egressKernSeq, egressKernLen = getKernSeqAndLen(sslWriteSyscallEvents)
		ingressKernSeq, ingressKernLen = getKernSeqAndLen(sslReadSyscallEvents)
	} else {
		// non-ssl connection kernSeq equals to seq
		ingressSeq = ingressMessage.Seq()
		ingressKernSeq = ingressSeq
		ingressKernLen = ingressMessage.ByteSize()
		egressSeq = egressMessage.Seq()
		egressKernSeq = egressSeq
		egressKernLen = egressMessage.ByteSize()
	}
	writeSyscallEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTSYSCALL_OUT, egressKernSeq, egressKernLen)
	readSyscallEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTSYSCALL_IN, ingressKernSeq, ingressKernLen)

	devOutEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTDEV_OUT, egressKernSeq, egressKernLen)
	nicIngressEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTNIC_IN, ingressKernSeq, ingressKernLen)
	userCopyEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTUSER_COPY, ingressKernSeq, ingressKernLen)
	tcpInEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTTCP_IN, ingressKernSeq, ingressKernLen)

	if len(nicIngressEvents) == 0 {
		nicIngressEvents = streamEvents.FindAndRemoveEventsBySeqAndLen(bpf.AgentStepTDEV_IN, ingressKernSeq, ingressKernLen)
	}
	events.sslReadSyscallEvents = sslReadSyscallEvents
	events.sslWriteSyscallEvents = sslWriteSyscallEvents

	events.writeSyscallEvents = writeSyscallEvents
	events.readSyscallEvents = readSyscallEvents

	events.devOutEvents = devOutEvents
	events.nicIngressEvents = nicIngressEvents
	events.userCopyEvents = userCopyEvents
	events.tcpInEvents = tcpInEvents

	events.ingressSeq = ingressSeq
	events.egressSeq = egressSeq
	events.ingressKernSeq = ingressKernSeq
	events.egressKernSeq = egressKernSeq
	events.ingressKernLen = ingressKernLen
	events.egressKernLen = egressKernLen

	events.egressMessage = egressMessage
	events.ingressMessage = ingressMessage
	return &events
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

	events := prepareEvents(r, connection)

	hasNicInEvents := len(events.nicIngressEvents) > 0
	hasDevOutEvents := len(events.devOutEvents) > 0
	hasReadSyscallEvents := len(events.readSyscallEvents) > 0
	hasWriteSyscallEvents := len(events.writeSyscallEvents) > 0
	hasUserCopyEvents := len(events.userCopyEvents) > 0
	hasTcpInEvents := len(events.tcpInEvents) > 0
	if connection.IsServerSide() {
		if hasNicInEvents {
			annotatedRecord.startTs = events.nicIngressEvents[0].GetTimestamp()
		}
		if hasDevOutEvents {
			annotatedRecord.endTs = events.devOutEvents[len(events.devOutEvents)-1].GetTimestamp()
		}
		if connection.IsSsl() {
			annotatedRecord.reqSslSize = events.ingressMessage.ByteSize()
			annotatedRecord.respSslSize = events.egressMessage.ByteSize()
		}
		annotatedRecord.reqSize = events.ingressKernLen
		annotatedRecord.respSize = events.egressKernLen
		if hasNicInEvents && hasDevOutEvents {
			annotatedRecord.totalDuration = float64(annotatedRecord.endTs) - float64(annotatedRecord.startTs)
		}
		if hasReadSyscallEvents && hasWriteSyscallEvents {
			annotatedRecord.blackBoxDuration = float64(events.writeSyscallEvents[len(events.writeSyscallEvents)-1].GetTimestamp()) - float64(events.readSyscallEvents[0].GetTimestamp())
		} else {
			annotatedRecord.blackBoxDuration = float64(events.egressMessage.TimestampNs()) - float64(events.ingressMessage.TimestampNs())
		}
		if hasUserCopyEvents && hasTcpInEvents {
			annotatedRecord.readFromSocketBufferDuration = float64(events.userCopyEvents[len(events.userCopyEvents)-1].GetTimestamp()) - float64(events.tcpInEvents[0].GetTimestamp())
		}
		annotatedRecord.reqSyscallEventDetails = KernEventsToEventDetails[SyscallEventDetail](events.readSyscallEvents)
		annotatedRecord.respSyscallEventDetails = KernEventsToEventDetails[SyscallEventDetail](events.writeSyscallEvents)
		annotatedRecord.reqNicEventDetails = KernEventsToEventDetails[NicEventDetail](events.nicIngressEvents)
		annotatedRecord.respNicEventDetails = KernEventsToEventDetails[NicEventDetail](events.devOutEvents)
	} else {
		if hasWriteSyscallEvents {
			annotatedRecord.startTs = events.writeSyscallEvents[0].GetTimestamp()
		} else {
			annotatedRecord.startTs = events.egressMessage.TimestampNs()
		}
		if hasReadSyscallEvents {
			annotatedRecord.endTs = events.readSyscallEvents[len(events.readSyscallEvents)-1].GetTimestamp()
		} else {
			annotatedRecord.endTs = events.ingressMessage.TimestampNs()
		}
		if connection.IsSsl() {
			annotatedRecord.reqSslSize = events.egressMessage.ByteSize()
			annotatedRecord.respSslSize = events.ingressMessage.ByteSize()
		}
		annotatedRecord.reqSize = events.egressKernLen
		annotatedRecord.respSize = events.ingressKernLen
		if hasReadSyscallEvents && hasWriteSyscallEvents {
			annotatedRecord.totalDuration = float64(annotatedRecord.endTs) - float64(annotatedRecord.startTs)
		} else {
			annotatedRecord.totalDuration = float64(events.ingressMessage.TimestampNs()) - float64(events.egressMessage.TimestampNs())
		}
		if hasNicInEvents && hasDevOutEvents {
			annotatedRecord.blackBoxDuration = float64(events.nicIngressEvents[len(events.nicIngressEvents)-1].GetTimestamp()) - float64(events.devOutEvents[0].GetTimestamp())
		}
		if hasUserCopyEvents && hasTcpInEvents {
			annotatedRecord.readFromSocketBufferDuration = float64(events.userCopyEvents[len(events.userCopyEvents)-1].GetTimestamp()) - float64(events.tcpInEvents[0].GetTimestamp())
		}
		annotatedRecord.reqSyscallEventDetails = KernEventsToEventDetails[SyscallEventDetail](events.writeSyscallEvents)
		annotatedRecord.respSyscallEventDetails = KernEventsToEventDetails[SyscallEventDetail](events.readSyscallEvents)
		annotatedRecord.reqNicEventDetails = KernEventsToEventDetails[NicEventDetail](events.devOutEvents)
		annotatedRecord.respNicEventDetails = KernEventsToEventDetails[NicEventDetail](events.nicIngressEvents)
	}
	streamEvents.DiscardEventsBySeq(events.egressKernSeq+uint64(events.egressKernLen), true)
	streamEvents.DiscardEventsBySeq(events.ingressKernSeq+uint64(events.ingressKernLen), false)
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

func getParsedMessageBySide(r protocol.Record, IsServerSide bool, direct DirectEnum) protocol.ParsedMessage {
	if !IsServerSide {
		if direct == DirectEgress {
			return r.Request()
		} else {
			return r.Response()
		}
	} else {
		if direct == DirectEgress {
			return r.Response()
		} else {
			return r.Request()
		}
	}
}
func (s *StatRecorder) RemoveRecord(tgidFd uint64) {
}
