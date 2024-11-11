package conn

import (
	"cmp"
	"fmt"
	"kyanos/bpf"
	"kyanos/common"
	"kyanos/monitor"
	"slices"

	"github.com/jefurry/logrus"
)

type KernEventStream struct {
	conn         *Connection4
	kernEvents   map[bpf.AgentStepT][]KernEvent
	sslInEvents  []SslEvent
	sslOutEvents []SslEvent
	maxLen       int

	egressDiscardSeq     uint64
	ingressDiscardSeq    uint64
	egressSslDiscardSeq  uint64
	ingressSslDiscardSeq uint64
}

func NewKernEventStream(conn *Connection4, maxLen int) *KernEventStream {
	stream := &KernEventStream{
		conn:       conn,
		kernEvents: make(map[bpf.AgentStepT][]KernEvent),
		maxLen:     maxLen,
	}
	monitor.RegisterMetricExporter(stream)
	return stream
}
func (s *KernEventStream) AddSslEvent(event *bpf.SslData) {
	s.discardSslEventsIfNeeded()
	var sslEvents []SslEvent
	if event.SslEventHeader.Ke.Step == bpf.AgentStepTSSL_IN {
		sslEvents = s.sslInEvents
	} else {
		sslEvents = s.sslOutEvents
	}
	index, found := slices.BinarySearchFunc(sslEvents, SslEvent{Seq: event.SslEventHeader.Ke.Seq}, func(i SslEvent, j SslEvent) int {
		return cmp.Compare(i.Seq, j.Seq)
	})
	if found {
		return
	}
	sslEvents = slices.Insert(sslEvents, index, SslEvent{
		Seq:       event.SslEventHeader.Ke.Seq,
		KernSeq:   event.SslEventHeader.SyscallSeq,
		Len:       int(event.SslEventHeader.Ke.Len),
		KernLen:   int(event.SslEventHeader.SyscallLen),
		Timestamp: event.SslEventHeader.Ke.Ts,
		Step:      event.SslEventHeader.Ke.Step,
	})
	if len(sslEvents) > s.maxLen {
		if common.ConntrackLog.Level >= logrus.DebugLevel {
			common.ConntrackLog.Debugf("ssl event size: %d exceed maxLen", len(sslEvents))
		}
	}
	for len(sslEvents) > s.maxLen {
		sslEvents = sslEvents[1:]
	}
	if event.SslEventHeader.Ke.Step == bpf.AgentStepTSSL_IN {
		s.sslInEvents = sslEvents
	} else {
		s.sslOutEvents = sslEvents
	}
}
func (s *KernEventStream) AddSyscallEvent(event *bpf.SyscallEventData) {
	s.AddKernEvent(&event.SyscallEvent.Ke)
}

func (s *KernEventStream) AddKernEvent(event *bpf.AgentKernEvt) {
	s.discardEventsIfNeeded()
	if event.Len > 0 {
		if _, ok := s.kernEvents[event.Step]; !ok {
			s.kernEvents[event.Step] = make([]KernEvent, 0)
		}

		kernEvtSlice := s.kernEvents[event.Step]
		index, found := slices.BinarySearchFunc(kernEvtSlice, KernEvent{seq: event.Seq}, func(i KernEvent, j KernEvent) int {
			return cmp.Compare(i.seq, j.seq)
		})
		var kernEvent *KernEvent
		if found {
			kernEvent = &kernEvtSlice[index]
		} else {
			kernEvent = &KernEvent{
				seq:       event.Seq,
				len:       int(event.Len),
				timestamp: event.Ts,
				step:      event.Step,
			}
		}

		if event.Step == bpf.AgentStepTDEV_OUT || event.Step == bpf.AgentStepTDEV_IN {
			if kernEvent.attributes == nil {
				kernEvent.attributes = make(map[string]any)
			}
			ifname, err := common.GetInterfaceNameByIndex(int(event.Ifindex), int(event.ConnIdS.TgidFd>>32))
			if err != nil {
				ifname = "unknown"
			}
			kernEvent.UpdateIfTimestampAttr(ifname, int64(event.Ts))
		} else if found {
			return
			// panic("found duplicate kern event on same seq")
		}
		kernEvtSlice = slices.Insert(kernEvtSlice, index, *kernEvent)
		if len(kernEvtSlice) > s.maxLen {
			if common.ConntrackLog.Level >= logrus.DebugLevel {
				common.ConntrackLog.Debugf("kern event stream size: %d exceed maxLen", len(kernEvtSlice))
			}
		}
		for len(kernEvtSlice) > s.maxLen {
			kernEvtSlice = kernEvtSlice[1:]
		}
		s.kernEvents[event.Step] = kernEvtSlice
	}
}

func (s *KernEventStream) FindSslEventsBySeqAndLen(step bpf.AgentStepT, seq uint64, len int) []SslEvent {
	var sslEvents []SslEvent
	if step == bpf.AgentStepTSSL_IN {
		sslEvents = s.sslInEvents
	} else {
		sslEvents = s.sslOutEvents
	}
	start := seq
	end := start + uint64(len)
	result := make([]SslEvent, 0)
	for _, each := range sslEvents {
		if each.Seq < start {
			continue
		}

		if each.Seq < end {
			result = append(result, each)
		} else {
			break
		}
	}

	return result
}

func (s *KernEventStream) FindEventsBySeqAndLen(step bpf.AgentStepT, seq uint64, len int) []KernEvent {
	events, ok := s.kernEvents[step]
	if !ok {
		return []KernEvent{}
	}
	start := seq
	end := start + uint64(len)
	result := make([]KernEvent, 0)
	for _, each := range events {
		if each.seq <= start && each.seq+uint64(each.len) >= start {
			result = append(result, each)
		} else if each.seq <= end && each.seq+uint64(each.len) >= end {
			result = append(result, each)
		} else if each.seq >= start && each.seq+uint64(each.len) <= end {
			result = append(result, each)
		} else if each.seq > end {
			break
		}
	}
	return result
}

func (s *KernEventStream) MarkNeedDiscardSeq(seq uint64, egress bool) {
	if egress {
		s.egressDiscardSeq = max(s.egressDiscardSeq, seq)
	} else {
		s.ingressDiscardSeq = max(s.ingressDiscardSeq, seq)
	}
}
func (s *KernEventStream) MarkNeedDiscardSslSeq(seq uint64, egress bool) {
	if egress {
		s.egressSslDiscardSeq = max(s.egressSslDiscardSeq, seq)
	} else {
		s.ingressSslDiscardSeq = max(s.ingressSslDiscardSeq, seq)
	}
}
func (s *KernEventStream) discardSslEventsIfNeeded() {
	if s.egressSslDiscardSeq != 0 {
		s.discardSslEventsBySeq(s.egressSslDiscardSeq, true)
	}
	if s.ingressSslDiscardSeq != 0 {
		s.discardSslEventsBySeq(s.ingressSslDiscardSeq, false)
	}
}

func (s *KernEventStream) discardEventsIfNeeded() {
	if s.egressDiscardSeq != 0 {
		s.discardEventsBySeq(s.egressDiscardSeq, true)
	}
	if s.ingressDiscardSeq != 0 {
		s.discardEventsBySeq(s.ingressDiscardSeq, false)
	}
}
func (s *KernEventStream) discardSslEventsBySeq(seq uint64, egress bool) {
	var oldevents *[]SslEvent
	if egress {
		oldevents = &s.sslOutEvents
	} else {
		oldevents = &s.sslInEvents
	}
	index, _ := slices.BinarySearchFunc(*oldevents, SslEvent{Seq: seq}, func(i SslEvent, j SslEvent) int {
		return cmp.Compare(i.Seq, j.Seq)
	})
	discardIdx := index
	if discardIdx > 0 {
		*oldevents = (*oldevents)[discardIdx:]
		// common.ConntrackLog.Debugf("Discarded ssl events(egress: %v) events num: %d, cur len: %d", egress, discardIdx, len(*oldevents))
	}
}
func (s *KernEventStream) discardEventsBySeq(seq uint64, egress bool) {
	for step, events := range s.kernEvents {
		if egress && !bpf.IsEgressStep(step) {
			continue
		}
		if !egress && !bpf.IsIngressStep(step) {
			continue
		}
		index, _ := slices.BinarySearchFunc(events, KernEvent{seq: seq}, func(i KernEvent, j KernEvent) int {
			return cmp.Compare(i.seq, j.seq)
		})
		discardIdx := index
		if discardIdx > 0 {
			s.kernEvents[step] = events[discardIdx:]
			// common.ConntrackLog.Debugf("Discarded kern events, step: %d(egress: %v) events num: %d, cur len: %d", step, egress, discardIdx, len(s.kernEvents[step]))
		}
	}
}

type KernEvent struct {
	seq        uint64
	len        int
	timestamp  uint64
	step       bpf.AgentStepT
	attributes map[string]any
}

func (kernevent *KernEvent) GetSeq() uint64 {
	return kernevent.seq
}

func (kernevent *KernEvent) GetLen() int {
	return kernevent.len
}

func (kernevent *KernEvent) GetTimestamp() uint64 {
	return kernevent.timestamp
}

func (kernevent *KernEvent) GetStep() bpf.AgentStepT {
	return kernevent.step
}

func (kernevent *KernEvent) GetAttributes() map[string]any {
	return kernevent.attributes
}

func (kernevent *KernEvent) UpdateIfTimestampAttr(ifname string, time int64) {
	kernevent.attributes["time-"+ifname] = time
}

type SslEvent struct {
	Seq       uint64
	KernSeq   uint64
	Len       int
	KernLen   int
	Timestamp uint64
	Step      bpf.AgentStepT
}

type TcpKernEvent struct {
	KernEvent
	tcpFlags int
}

var _ monitor.MetricExporter = &KernEventStream{}

func (s *KernEventStream) ExportMetrics() monitor.MetricMap {
	allEventsNum := 0
	for _, events := range s.kernEvents {
		allEventsNum += len(events)
	}
	return monitor.MetricMap{
		"events_num": float64(allEventsNum),
	}
}

func (s *KernEventStream) MetricGroupName() string {
	return fmt.Sprintf("stream_events-%s", s.conn.Identity())
}
