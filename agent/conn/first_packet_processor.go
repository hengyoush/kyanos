package conn

import (
	"kyanos/bpf"
	"kyanos/common"
	"time"
)

type timedFirstPacketEvent struct {
	FirstPacketEvent *bpf.AgentFirstPacketEvt
	Timestamp        uint64
}

type agentKernEvtWithConn struct {
	*bpf.AgentKernEvt
	*Connection4
}

type FirstPacketProcessor struct {
	events   []*timedFirstPacketEvent
	ch       chan *bpf.AgentFirstPacketEvt
	channels []chan *agentKernEvtWithConn
}

func NewFirstPacketProcessor(ch chan *bpf.AgentFirstPacketEvt, channels []chan *agentKernEvtWithConn) *FirstPacketProcessor {
	return &FirstPacketProcessor{
		ch:       ch,
		channels: channels,
		events:   make([]*timedFirstPacketEvent, 0),
	}
}

func (p *FirstPacketProcessor) Start() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case evt := <-p.ch:
			p.events = append(p.events, &timedFirstPacketEvent{
				FirstPacketEvent: evt,
				Timestamp:        uint64(time.Now().UnixNano() / 1e6),
			})
		case <-ticker.C:
			p.processEvents()
		}
	}
}

func (p *FirstPacketProcessor) processEvents() {
	now := uint64(time.Now().UnixNano() / 1e6)
	var lastProcessedIndex int = -1

	for i, event := range p.events {
		if now-event.Timestamp > 50 {
			// Process the event
			p.processEvent(event)
			lastProcessedIndex = i
		} else {
			break
		}
	}

	// Truncate the slice to remove processed events
	if lastProcessedIndex >= 0 {
		p.events = p.events[lastProcessedIndex+1:]
	}
}

func (p *FirstPacketProcessor) processEvent(event *timedFirstPacketEvent) {
	// Processing logic goes here
	conn, ok := ConnectionMap.Load(event.FirstPacketEvent.Key)
	if ok {
		channel := p.channels[int(conn.(*Connection4).TgidFd)%len(p.channels)]
		connId := &bpf.AgentConnIdS_t{
			TgidFd:  conn.(*Connection4).TgidFd,
			NoTrace: false,
		}
		common.BPFEventLog.Debugf("%s First packet event: %+v", conn.(*Connection4).ToString(), event.FirstPacketEvent)
		kernEvent := timedFirstPacketEventAsKernEvent(event, connId)
		channel <- &agentKernEvtWithConn{
			AgentKernEvt: kernEvent,
			Connection4:  conn.(*Connection4),
		}

	}
}

func (p *FirstPacketProcessor) extractTgidFdFromSockKey(key *bpf.AgentSockKey) (*bpf.AgentConnIdS_t, error) {
	sockKeyConnIdMap := bpf.GetMapFromObjs(bpf.Objs, "SockKeyConnIdMap")
	var connIds bpf.AgentConnIdS_t
	err := sockKeyConnIdMap.Lookup(key, &connIds)
	if err == nil && !connIds.NoTrace {
		return &connIds, nil
	}
	return nil, err
}

func timedFirstPacketEventAsKernEvent(event *timedFirstPacketEvent, connIds *bpf.AgentConnIdS_t) *bpf.AgentKernEvt {
	return &bpf.AgentKernEvt{
		Ts:      event.FirstPacketEvent.Ts,
		TsDelta: 0,
		Seq:     1,
		Len:     event.FirstPacketEvent.Len,
		Flags:   event.FirstPacketEvent.Flags,
		Ifindex: event.FirstPacketEvent.Ifindex,
		ConnIdS: *connIds,
		Step:    event.FirstPacketEvent.Step,
	}
}
