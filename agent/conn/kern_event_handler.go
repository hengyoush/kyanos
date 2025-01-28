package conn

import (
	"cmp"
	"fmt"
	"kyanos/bpf"
	"kyanos/common"
	"kyanos/monitor"
	"slices"
	"strings"
	"sync"

	"github.com/jefurry/logrus"
)

type KernEventStream struct {
	conn           *Connection4
	kernEvents     map[bpf.AgentStepT]*common.RingBuffer
	kernEventsMu   sync.RWMutex
	sslInEvents    []SslEvent
	sslOutEvents   []SslEvent
	sslInEventsMu  sync.RWMutex
	sslOutEventsMu sync.RWMutex
	maxLen         int

	egressDiscardSeq     uint64
	ingressDiscardSeq    uint64
	egressSslDiscardSeq  uint64
	ingressSslDiscardSeq uint64
}

func NewKernEventStream(conn *Connection4, maxLen int) *KernEventStream {
	stream := &KernEventStream{
		conn:       conn,
		kernEvents: make(map[bpf.AgentStepT]*common.RingBuffer),
		maxLen:     maxLen,
	}
	monitor.RegisterMetricExporter(stream)
	return stream
}
func (s *KernEventStream) AddSslEvent(event *bpf.SslData) {
	if event.SslEventHeader.Ke.Step == bpf.AgentStepTSSL_IN {
		s.sslInEventsMu.Lock()
		defer s.sslInEventsMu.Unlock()
		s.discardSslEventsIfNeeded(true)
	} else {
		s.sslOutEventsMu.Lock()
		defer s.sslOutEventsMu.Unlock()
		s.discardSslEventsIfNeeded(false)
	}
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
		Seq:     event.SslEventHeader.Ke.Seq,
		KernSeq: event.SslEventHeader.SyscallSeq,
		Len:     int(event.SslEventHeader.Ke.Len),
		KernLen: int(event.SslEventHeader.SyscallLen),
		startTs: event.SslEventHeader.Ke.Ts,
		tsDelta: event.SslEventHeader.Ke.TsDelta,
		Step:    event.SslEventHeader.Ke.Step,
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

func (s *KernEventStream) AddKernEvent(event *bpf.AgentKernEvt) bool {
	s.kernEventsMu.Lock()
	defer s.kernEventsMu.Unlock()
	s.discardEventsIfNeeded()
	if event.Len > 0 {
		if _, ok := s.kernEvents[event.Step]; !ok {
			s.kernEvents[event.Step] = common.NewRingBuffer(s.maxLen)
		}

		kernEvtRingBuffer := s.kernEvents[event.Step]
		index, found := kernEvtRingBuffer.BinarySearch(KernEvent{seq: event.Seq}, func(i any, j any) int {
			return cmp.Compare(i.(KernEvent).seq, j.(KernEvent).seq)
		})
		isNicEvnt := event.Step == bpf.AgentStepTDEV_OUT || event.Step == bpf.AgentStepTDEV_IN

		var kernEvent *KernEvent
		if found {
			_oldKernEvent, _ := kernEvtRingBuffer.ReadIndex(index)
			oldKernEvent := _oldKernEvent.(KernEvent)
			if oldKernEvent.startTs > event.Ts && !isNicEvnt {
				// this is a duplicate event which belongs to a future conn
				oldKernEvent.seq = event.Seq
				oldKernEvent.len = int(event.Len)
				oldKernEvent.startTs = event.Ts
				oldKernEvent.tsDelta = event.TsDelta
				oldKernEvent.step = event.Step
				kernEvent = &oldKernEvent
			} else if !isNicEvnt {
				return false
			} else {
				kernEvent = &oldKernEvent
			}
		} else {
			kernEvent = &KernEvent{
				seq:     event.Seq,
				len:     int(event.Len),
				startTs: event.Ts,
				tsDelta: event.TsDelta,
				step:    event.Step,
			}
		}

		if isNicEvnt {
			if kernEvent.attributes == nil {
				kernEvent.attributes = make(map[string]any)
			}
			ifname, err := getInterfaceNameByIndex(int(event.Ifindex), int(event.ConnIdS.TgidFd>>32))
			if err != nil {
				ifname = "unknown"
			}
			updated := kernEvent.UpdateIfTimestampAttr(ifname, int64(event.Ts))
			if !updated {
				return false
			}
		}
		if !found {
			if err := kernEvtRingBuffer.Insert(index, *kernEvent); err != nil {
				common.ConntrackLog.Debugf("kern event stream size: %d exceed maxLen", kernEvtRingBuffer.MaxCapacity())
				return false
			}
		}
	}
	return true
}

func (s *KernEventStream) FindSslEventsBySeqAndLen(step bpf.AgentStepT, seq uint64, len int) []SslEvent {
	if step == bpf.AgentStepTSSL_IN {
		s.sslInEventsMu.RLock()
		defer s.sslInEventsMu.RUnlock()
	} else {
		s.sslOutEventsMu.RLock()
		defer s.sslOutEventsMu.RUnlock()
	}
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
	s.kernEventsMu.RLock()
	defer s.kernEventsMu.RUnlock()
	events, ok := s.kernEvents[step]
	if !ok {
		return []KernEvent{}
	}
	start := seq
	end := start + uint64(len)
	result := make([]KernEvent, 0)
	events.ForEach(func(i any) bool {
		each := i.(KernEvent)
		if each.seq <= start && each.seq+uint64(each.len) > start {
			result = append(result, each)
		} else if each.seq < end && each.seq+uint64(each.len) >= end {
			result = append(result, each)
		} else if each.seq >= start && each.seq+uint64(each.len) <= end {
			result = append(result, each)
		} else if each.seq > end {
			return false
		}
		return true
	})
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
func (s *KernEventStream) discardSslEventsIfNeeded(isIn bool) {
	if isIn {
		if s.ingressSslDiscardSeq != 0 {
			s.discardSslEventsBySeq(s.ingressSslDiscardSeq, false)
		}
	} else {
		if s.egressSslDiscardSeq != 0 {
			s.discardSslEventsBySeq(s.egressSslDiscardSeq, true)
		}
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
		index, _ := events.BinarySearch(KernEvent{seq: seq}, func(i any, j any) int {
			return cmp.Compare(i.(KernEvent).seq, j.(KernEvent).seq)
		})
		discardIdx := index
		if discardIdx > 0 {
			events.DiscardBeforeIndex(discardIdx)
			// common.ConntrackLog.Debugf("Discarded kern events, step: %d(egress: %v) events num: %d, cur len: %d", step, egress, discardIdx, len(s.kernEvents[step]))
		}
	}
}

type KernEvent struct {
	seq        uint64
	len        int
	startTs    uint64
	tsDelta    uint32
	step       bpf.AgentStepT
	attributes map[string]any
}

func (kernevent *KernEvent) GetSeq() uint64 {
	return kernevent.seq
}

func (kernevent *KernEvent) GetLen() int {
	return kernevent.len
}

func (kernevent *KernEvent) GetStartTs() uint64 {
	return kernevent.startTs
}

func (kernevent *KernEvent) GetTsDelta() uint32 {
	return kernevent.tsDelta
}

func (kernevent *KernEvent) GetEndTs() uint64 {
	return kernevent.startTs + uint64(kernevent.tsDelta)
}

func (kernevent *KernEvent) GetStep() bpf.AgentStepT {
	return kernevent.step
}

func (kernevent *KernEvent) GetAttributes() map[string]any {
	return kernevent.attributes
}

func (kernevent *KernEvent) UpdateIfTimestampAttr(ifname string, time int64) bool {
	if timestamp, ok := kernevent.attributes["time-"+ifname]; ok {
		if ts, valid := timestamp.(int64); valid {
			if ts < time {
				return false
			}
		}
	}

	kernevent.attributes["time-"+ifname] = time
	return true
}

func (kernevent *KernEvent) GetMaxIfItmestampAttr() (int64, string, bool) {
	maxTimestamp := int64(0)
	var maxIfname string
	found := false
	for key, value := range kernevent.attributes {
		if strings.HasPrefix(key, "time-") {
			if timestamp, ok := value.(int64); ok {
				if timestamp > maxTimestamp {
					maxTimestamp = timestamp
					maxIfname = strings.TrimPrefix(key, "time-")
					found = true
				}
			}
		}
	}
	return maxTimestamp, maxIfname, found
}

func (kernevent *KernEvent) GetMinIfItmestampAttr() (int64, string, bool) {
	minTimestamp := int64(^uint64(0) >> 1) // Max int64 value
	var minIfname string
	found := false
	for key, value := range kernevent.attributes {
		if strings.HasPrefix(key, "time-") {
			if timestamp, ok := value.(int64); ok {
				if timestamp < minTimestamp {
					minTimestamp = timestamp
					minIfname = strings.TrimPrefix(key, "time-")
					found = true
				}
			}
		}
	}
	return minTimestamp, minIfname, found
}

func (kernevent *KernEvent) GetTimestampByIfname(ifname string) (int64, bool) {
	key := "time-" + ifname
	if timestamp, ok := kernevent.attributes[key]; ok {
		if ts, valid := timestamp.(int64); valid {
			return ts, true
		}
	}
	return 0, false
}

type SslEvent struct {
	Seq     uint64
	KernSeq uint64
	Len     int
	KernLen int
	startTs uint64
	tsDelta uint32
	Step    bpf.AgentStepT
}

func (s *SslEvent) GetStartTs() uint64 {
	return s.startTs
}

func (s *SslEvent) GetEndTs() uint64 {
	return s.startTs + uint64(s.tsDelta)
}

type TcpKernEvent struct {
	KernEvent
	tcpFlags int
}

var _ monitor.MetricExporter = &KernEventStream{}

func (s *KernEventStream) ExportMetrics() monitor.MetricMap {
	allEventsNum := 0
	for _, events := range s.kernEvents {
		allEventsNum += events.Size()
	}
	return monitor.MetricMap{
		"events_num": float64(allEventsNum),
	}
}

func (s *KernEventStream) MetricGroupName() string {
	return fmt.Sprintf("stream_events-%s", s.conn.Identity())
}
