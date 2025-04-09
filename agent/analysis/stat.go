package analysis

import (
	analysisCommon "kyanos/agent/analysis/common"
	. "kyanos/agent/common"
	"kyanos/agent/conn"
	"kyanos/agent/protocol"
	"kyanos/bpf"
	. "kyanos/common"
	"math"

	"github.com/jefurry/logrus"
)

var outputLog *logrus.Logger = logrus.New()
var traceDevEvent bool
var traceSocketEvent bool

type StatRecorder struct {
}

func InitStatRecorder(options *AgentOptions) *StatRecorder {
	sr := new(StatRecorder)
	traceDevEvent = options.WatchOptions.TraceDevEvent
	traceSocketEvent = options.WatchOptions.TraceSocketEvent
	return sr
}

func CreateAnnotedRecord() *analysisCommon.AnnotatedRecord {
	return &analysisCommon.AnnotatedRecord{
		StartTs:                      0,
		EndTs:                        0,
		ReqSize:                      -1,
		RespSize:                     -1,
		TotalDuration:                -1,
		BlackBoxDuration:             -1,
		ReadFromSocketBufferDuration: -1,
		ReqSyscallEventDetails:       make([]analysisCommon.SyscallEventDetail, 0),
		RespSyscallEventDetails:      make([]analysisCommon.SyscallEventDetail, 0),
		ReqNicEventDetails:           make([]analysisCommon.NicEventDetail, 0),
		RespNicEventDetails:          make([]analysisCommon.NicEventDetail, 0),
	}
}

func timeUnitName(nano bool) string {
	if nano {
		return "ns"
	} else {
		return "ms"
	}
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
	egressMessage, ingressMessage                        protocol.ParsedMessage
	ingressSeq, egressSeq, ingressKernSeq, egressKernSeq uint64
	ingressKernLen, egressKernLen                        int
}

func getKernSeqAndLen(syscallEvents []conn.SslEvent) (uint64, int) {
	var syscallSeq int64 = -1
	var syscallLen int
	if len(syscallEvents) > 0 {
		for idx := 0; idx < len(syscallEvents); idx++ {
			each := syscallEvents[idx]
			if each.KernSeq != 0 || each.KernLen != 0 {
				syscallSeq = int64(each.KernSeq)
				break
			}
		}
		if syscallSeq == -1 {
			return 0, 0
		}

		for idx := len(syscallEvents) - 1; idx >= 0; idx-- {
			each := syscallEvents[idx]
			if each.KernSeq != 0 || each.KernLen != 0 {
				syscallLen = int(int64(each.KernLen) + int64(each.KernSeq) - syscallSeq)
				break
			}
		}

		return uint64(syscallSeq), syscallLen
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
		sslWriteSyscallEvents = streamEvents.FindSslEventsBySeqAndLen(bpf.AgentStepTSSL_OUT, egressMessage.Seq(), egressMessage.ByteSize())
		sslReadSyscallEvents = streamEvents.FindSslEventsBySeqAndLen(bpf.AgentStepTSSL_IN, ingressMessage.Seq(), ingressMessage.ByteSize())

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
	writeSyscallEvents = streamEvents.FindEventsBySeqAndLen(bpf.AgentStepTSYSCALL_OUT, egressKernSeq, egressKernLen)
	readSyscallEvents = streamEvents.FindEventsBySeqAndLen(bpf.AgentStepTSYSCALL_IN, ingressKernSeq, ingressKernLen)

	if traceDevEvent {
		devOutEvents = streamEvents.FindEventsBySeqAndLen(bpf.AgentStepTDEV_OUT, egressKernSeq, egressKernLen)
		nicIngressEvents = streamEvents.FindEventsBySeqAndLen(bpf.AgentStepTNIC_IN, ingressKernSeq, ingressKernLen)
		if len(nicIngressEvents) == 0 {
			nicIngressEvents = streamEvents.FindEventsBySeqAndLen(bpf.AgentStepTDEV_IN, ingressKernSeq, ingressKernLen)
		}
	}
	if traceSocketEvent {
		userCopyEvents = streamEvents.FindEventsBySeqAndLen(bpf.AgentStepTUSER_COPY, ingressKernSeq, ingressKernLen)
		tcpInEvents = streamEvents.FindEventsBySeqAndLen(bpf.AgentStepTTCP_IN, ingressKernSeq, ingressKernLen)
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

func (s *StatRecorder) ReceiveRecord(r protocol.Record, connection *conn.Connection4, recordsChannel chan<- *analysisCommon.AnnotatedRecord) error {
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
		IsSsl:      connection.IsSsl(),
	}

	events := prepareEvents(r, connection)

	hasNicInEvents := len(events.nicIngressEvents) > 0
	hasDevOutEvents := len(events.devOutEvents) > 0
	hasReadSyscallEvents := len(events.readSyscallEvents) > 0
	hasWriteSyscallEvents := len(events.writeSyscallEvents) > 0
	hasUserCopyEvents := len(events.userCopyEvents) > 0
	hasTcpInEvents := len(events.tcpInEvents) > 0
	if connection.IsServerSide() {
		// why not use nicIngressEvents[0] directly?
		// because we could missed some nicIngressEvents, the total duration may be negative
		annotatedRecord.StartTs = math.MaxUint64
		if hasNicInEvents {
			nicInTimestamp, _, ok := events.nicIngressEvents[0].GetMinIfItmestampAttr()
			if ok {
				annotatedRecord.StartTs = min(uint64(nicInTimestamp), annotatedRecord.StartTs)
			}
		} else if hasTcpInEvents {
			annotatedRecord.StartTs = min(events.tcpInEvents[0].GetStartTs(), annotatedRecord.StartTs)
		} else if hasUserCopyEvents {
			annotatedRecord.StartTs = min(events.userCopyEvents[0].GetStartTs(), annotatedRecord.StartTs)
		} else if hasReadSyscallEvents {
			annotatedRecord.StartTs = min(events.readSyscallEvents[0].GetStartTs(), annotatedRecord.StartTs)
		}
		annotatedRecord.EndTs = math.MaxUint64
		if hasDevOutEvents {
			devOutTimestamp, _, ok := events.devOutEvents[len(events.devOutEvents)-1].GetMaxIfTimestampAttr()
			if ok {
				annotatedRecord.EndTs = uint64(devOutTimestamp)
			}
		} else if hasWriteSyscallEvents {
			annotatedRecord.EndTs = events.writeSyscallEvents[len(events.writeSyscallEvents)-1].GetEndTs()
		}
		if connection.IsSsl() {
			annotatedRecord.ReqPlainTextSize = events.ingressMessage.ByteSize()
			annotatedRecord.RespPlainTextSize = events.egressMessage.ByteSize()
		}
		canCalculateReadPathTime := !connection.IsSsl() || isKernEvtCanMatchSslEvt(events.sslReadSyscallEvents)
		canCalculateWritePathTime := !connection.IsSsl() || isKernEvtCanMatchSslEvt(events.sslWriteSyscallEvents)
		annotatedRecord.ReqSize = events.ingressKernLen
		annotatedRecord.RespSize = events.egressKernLen
		if annotatedRecord.StartTs != math.MaxUint64 && annotatedRecord.EndTs != math.MaxUint64 &&
			(canCalculateReadPathTime && canCalculateWritePathTime) {
			annotatedRecord.TotalDuration = float64(annotatedRecord.EndTs) - float64(annotatedRecord.StartTs)
		}
		if hasReadSyscallEvents && hasWriteSyscallEvents && canCalculateReadPathTime && canCalculateWritePathTime {
			annotatedRecord.BlackBoxDuration = float64(events.writeSyscallEvents[len(events.writeSyscallEvents)-1].GetEndTs()) - float64(events.readSyscallEvents[0].GetStartTs())
		} else {
			annotatedRecord.BlackBoxDuration = float64(events.egressMessage.TimestampNs()) - float64(events.ingressMessage.TimestampNs())
		}
		if hasUserCopyEvents && hasTcpInEvents && canCalculateReadPathTime {
			annotatedRecord.ReadFromSocketBufferDuration = float64(events.userCopyEvents[len(events.userCopyEvents)-1].GetStartTs()) - float64(events.tcpInEvents[0].GetStartTs())
		}
		if hasTcpInEvents && hasNicInEvents && canCalculateWritePathTime {
			annotatedRecord.CopyToSocketBufferDuration = float64(events.tcpInEvents[len(events.tcpInEvents)-1].GetStartTs() - events.nicIngressEvents[0].GetStartTs())
		}
		if !traceDevEvent {
			annotatedRecord.TotalDuration = annotatedRecord.BlackBoxDuration
		}
		if !traceSocketEvent && hasNicInEvents && canCalculateReadPathTime && hasReadSyscallEvents {
			if nicInTimestamp, _, ok := events.nicIngressEvents[0].GetMinIfItmestampAttr(); ok {
				annotatedRecord.ReadFromSocketBufferDuration = float64(events.readSyscallEvents[len(events.readSyscallEvents)-1].GetEndTs() - uint64(nicInTimestamp))
			}
		}
		annotatedRecord.ReqSyscallEventDetails = KernEventsToEventDetails[analysisCommon.SyscallEventDetail](events.readSyscallEvents)
		annotatedRecord.RespSyscallEventDetails = KernEventsToEventDetails[analysisCommon.SyscallEventDetail](events.writeSyscallEvents)
		annotatedRecord.ReqNicEventDetails = KernEventsToNicEventDetails(events.nicIngressEvents)
		annotatedRecord.RespNicEventDetails = KernEventsToNicEventDetails(events.devOutEvents)
	} else {
		canCalculateReadPathTime := !connection.IsSsl() || isKernEvtCanMatchSslEvt(events.sslReadSyscallEvents)
		canCalculateWritePathTime := !connection.IsSsl() || isKernEvtCanMatchSslEvt(events.sslWriteSyscallEvents)
		if hasWriteSyscallEvents && canCalculateWritePathTime {
			annotatedRecord.StartTs = findMinTimestamp(events.writeSyscallEvents, true)
		} else {
			annotatedRecord.StartTs = events.egressMessage.TimestampNs()
		}
		if hasReadSyscallEvents && canCalculateReadPathTime {
			annotatedRecord.EndTs = findMaxTimestamp(events.readSyscallEvents, false)
		} else {
			annotatedRecord.EndTs = events.ingressMessage.TimestampNs()
		}
		if connection.IsSsl() {
			annotatedRecord.ReqPlainTextSize = events.egressMessage.ByteSize()
			annotatedRecord.RespPlainTextSize = events.ingressMessage.ByteSize()
		}
		annotatedRecord.ReqSize = events.egressKernLen
		annotatedRecord.RespSize = events.ingressKernLen
		if hasReadSyscallEvents && hasWriteSyscallEvents && canCalculateReadPathTime && canCalculateWritePathTime {
			annotatedRecord.TotalDuration = float64(annotatedRecord.EndTs) - float64(annotatedRecord.StartTs)
		} else {
			annotatedRecord.TotalDuration = float64(events.ingressMessage.TimestampNs()) - float64(events.egressMessage.TimestampNs())
		}
		if hasNicInEvents && hasDevOutEvents && canCalculateReadPathTime && canCalculateWritePathTime {
			nicIngressTimestamp := int64(0)
			for _, nicIngressEvent := range events.nicIngressEvents {
				_nicIngressTimestamp, _, ok := nicIngressEvent.GetMinIfItmestampAttr()
				if ok {
					nicIngressTimestamp = max(nicIngressTimestamp, _nicIngressTimestamp)
				}
			}

			if nicIngressTimestamp != 0 {
				nicEgressTimestamp := int64(math.MaxInt64)
				for _, devOutEvent := range events.devOutEvents {
					_nicEgressTimestamp, _, ok := devOutEvent.GetMaxIfTimestampAttr()
					if ok {
						nicEgressTimestamp = min(nicEgressTimestamp, _nicEgressTimestamp)
					}
				}
				if nicEgressTimestamp != int64(math.MaxInt64) {
					annotatedRecord.BlackBoxDuration = float64(nicIngressTimestamp) - float64(nicEgressTimestamp)
				} else {
					annotatedRecord.BlackBoxDuration = -1
				}
				nicEgressTimestamp++
			} else {
				annotatedRecord.BlackBoxDuration = -1
			}
		}
		if (hasUserCopyEvents || hasReadSyscallEvents) && hasTcpInEvents && canCalculateReadPathTime {
			var readFromEndTime float64
			if hasUserCopyEvents {
				readFromEndTime = float64(events.userCopyEvents[len(events.userCopyEvents)-1].GetStartTs())
			} else {
				readFromEndTime = float64(events.readSyscallEvents[len(events.readSyscallEvents)-1].GetEndTs())
			}
			annotatedRecord.ReadFromSocketBufferDuration = readFromEndTime - float64(events.tcpInEvents[0].GetStartTs())
		}
		if hasTcpInEvents && hasNicInEvents && canCalculateReadPathTime {
			annotatedRecord.CopyToSocketBufferDuration = float64(events.tcpInEvents[len(events.tcpInEvents)-1].GetStartTs() - events.nicIngressEvents[0].GetStartTs())
		}
		if !traceSocketEvent && hasNicInEvents && canCalculateReadPathTime && hasReadSyscallEvents {
			if _nicIngressTimestamp, _, ok := events.nicIngressEvents[0].GetMinIfItmestampAttr(); ok {
				annotatedRecord.ReadFromSocketBufferDuration = float64(events.readSyscallEvents[len(events.readSyscallEvents)-1].GetEndTs() - uint64(_nicIngressTimestamp))
			}

		}
		annotatedRecord.ReqSyscallEventDetails = KernEventsToEventDetails[analysisCommon.SyscallEventDetail](events.writeSyscallEvents)
		annotatedRecord.RespSyscallEventDetails = KernEventsToEventDetails[analysisCommon.SyscallEventDetail](events.readSyscallEvents)
		annotatedRecord.ReqNicEventDetails = KernEventsToNicEventDetails(events.devOutEvents)
		annotatedRecord.RespNicEventDetails = KernEventsToNicEventDetails(events.nicIngressEvents)
	}

	streamEvents.MarkNeedDiscardSeq(events.egressKernSeq+uint64(events.egressKernLen), true)
	streamEvents.MarkNeedDiscardSeq(events.ingressKernSeq+uint64(events.ingressKernLen), false)
	if connection.IsSsl() {
		streamEvents.MarkNeedDiscardSslSeq(events.egressSeq+uint64(events.egressMessage.ByteSize()), true)
		streamEvents.MarkNeedDiscardSslSeq(events.ingressSeq+uint64(events.ingressMessage.ByteSize()), false)
	}

	if recordsChannel == nil {
		outputLog.Infoln(annotatedRecord.String(analysisCommon.AnnotatedRecordToStringOptions{
			Nano: false,
			MetricTypeSet: analysisCommon.MetricTypeSet{
				analysisCommon.ResponseSize:                 false,
				analysisCommon.RequestSize:                  false,
				analysisCommon.ReadFromSocketBufferDuration: true,
				analysisCommon.BlackBoxDuration:             true,
				analysisCommon.TotalDuration:                true,
			}, IncludeSyscallStat: true,
			IncludeConnDesc: true,
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

// some syscalls are not nested int ssl events, so we need to check if all ssl events have kernLen>0
// otherwise, we can't calculate the duration related to kern events because the kern seq is not valid
func isKernEvtCanMatchSslEvt(events []conn.SslEvent) bool {
	for _, each := range events {
		if each.KernLen == 0 {
			return false
		}
	}
	return true
}

func findMaxTimestamp(events []conn.KernEvent, useStartTs bool) uint64 {
	var maxTimestamp uint64 = 0
	for _, each := range events {
		if useStartTs {
			maxTimestamp = max(maxTimestamp, each.GetStartTs())
		} else {
			maxTimestamp = max(maxTimestamp, each.GetEndTs())
		}
	}
	return maxTimestamp
}

func findMinTimestamp(events []conn.KernEvent, useStartTs bool) uint64 {
	var minTimestamp uint64 = math.MaxUint64
	for _, each := range events {
		if useStartTs {
			minTimestamp = min(minTimestamp, each.GetStartTs())
		} else {
			minTimestamp = min(minTimestamp, each.GetEndTs())
		}
	}
	return minTimestamp
}

func KernEventsToEventDetails[K analysisCommon.PacketEventDetail | analysisCommon.SyscallEventDetail](kernEvents []conn.KernEvent) []K {
	if len(kernEvents) == 0 {
		return []K{}
	}
	result := make([]K, 0)
	for _, each := range kernEvents {
		result = append(result, K{
			ByteSize:  each.GetLen(),
			Timestamp: each.GetStartTs(),
		})
	}
	return result
}
func KernEventsToNicEventDetails(kernEvents []conn.KernEvent) []analysisCommon.NicEventDetail {
	if len(kernEvents) == 0 {
		return []analysisCommon.NicEventDetail{}
	}
	result := make([]analysisCommon.NicEventDetail, 0)
	for _, each := range kernEvents {
		result = append(result, analysisCommon.NicEventDetail{
			PacketEventDetail: analysisCommon.PacketEventDetail{

				ByteSize:  each.GetLen(),
				Timestamp: each.GetStartTs(),
			},
			Attributes: each.GetAttributes(),
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
