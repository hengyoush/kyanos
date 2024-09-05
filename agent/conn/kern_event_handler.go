package conn

import (
	"cmp"
	"kyanos/bpf"
	"slices"
)

type KernEventStream struct {
	conn       *Connection4
	kernEvents map[bpf.AgentStepT][]KernEvent
	maxLen     int
}

func NewKernEventStream(conn *Connection4, maxLen int) *KernEventStream {
	return &KernEventStream{
		conn:       conn,
		kernEvents: make(map[bpf.AgentStepT][]KernEvent),
		maxLen:     maxLen,
	}
}

func (s *KernEventStream) AddSyscallEvent(event *bpf.SyscallEventData) {
	s.AddKernEvent(&event.SyscallEvent.Ke)
}

func (s *KernEventStream) AddKernEvent(event *bpf.AgentKernEvt) {
	if event.Len > 0 {
		if s.kernEvents[event.Step] == nil {
			s.kernEvents[event.Step] = make([]KernEvent, 0)
		}

		kernEvtSlice := s.kernEvents[event.Step]
		index, found := slices.BinarySearchFunc(kernEvtSlice, KernEvent{seq: event.Seq}, func(i KernEvent, j KernEvent) int {
			return cmp.Compare(i.seq, j.seq)
		})
		if found {
			return
			// panic("found duplicate kern event on same seq")
		}
		kernEvtSlice = slices.Insert(kernEvtSlice, index, KernEvent{
			seq:       event.Seq,
			len:       int(event.Len),
			timestamp: event.Ts,
			step:      event.Step,
		})
		for len(kernEvtSlice) > s.maxLen {
			kernEvtSlice = kernEvtSlice[1:]
		}
	}
}

func (s *KernEventStream) FindAndRemoveEventsBySeqAndLen(step bpf.AgentStepT, seq uint64, len int) []KernEvent {
	events, ok := s.kernEvents[step]
	if !ok {
		return []KernEvent{}
	}
	start := seq
	end := start + uint64(len)
	needsRemoveLastIndex := -1
	result := make([]KernEvent, 0)
	for index, each := range events {
		if each.seq < start {
			needsRemoveLastIndex = index
			continue
		}

		if each.seq < end {
			result = append(result, each)
			needsRemoveLastIndex = index
		} else {
			break
		}
	}
	if needsRemoveLastIndex != -1 {
		s.kernEvents[step] = events[needsRemoveLastIndex+1:]
	}
	return result
}

type KernEvent struct {
	seq       uint64
	len       int
	timestamp uint64
	step      bpf.AgentStepT
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

type TcpKernEvent struct {
	KernEvent
	tcpFlags int
}
