package conn

import (
	"context"
	"fmt"
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"
	"sync"
	"time"

	"github.com/jefurry/logrus"
)

type ProcessorManager struct {
	processors  []*Processor
	wg          *sync.WaitGroup
	ctx         context.Context
	connManager *ConnManager
	cancel      context.CancelFunc
}

func InitProcessorManager(n int, connManager *ConnManager, filter protocol.ProtocolFilter,
	latencyFilter protocol.LatencyFilter, sizeFilter protocol.SizeFilter, side common.SideEnum, conntrackCloseWaitTimeMills int) *ProcessorManager {
	pm := new(ProcessorManager)
	pm.processors = make([]*Processor, n)
	pm.wg = new(sync.WaitGroup)
	pm.ctx, pm.cancel = context.WithCancel(context.Background())
	pm.connManager = connManager
	for i := 0; i < n; i++ {
		pm.processors[i] = initProcessor("Processor-"+fmt.Sprint(i), pm.wg, pm.ctx, pm.connManager, filter, latencyFilter, sizeFilter, side, conntrackCloseWaitTimeMills)
		go pm.processors[i].run()
		pm.wg.Add(1)
	}
	return pm
}

func (pm *ProcessorManager) GetProcessor(i int) *Processor {
	if i < 0 || i >= len(pm.processors) {
		return nil
	}
	return pm.processors[i]
}

func (pm *ProcessorManager) GetSyscallEventsChannels() []chan *bpf.SyscallEventData {
	var channels []chan *bpf.SyscallEventData = make([]chan *bpf.SyscallEventData, 0)
	for _, each := range pm.processors {
		channels = append(channels, each.syscallEvents)
	}
	return channels
}

func (pm *ProcessorManager) GetSslEventsChannels() []chan *bpf.SslData {
	var channels []chan *bpf.SslData = make([]chan *bpf.SslData, 0)
	for _, each := range pm.processors {
		channels = append(channels, each.sslEvents)
	}
	return channels
}

func (pm *ProcessorManager) GetConnEventsChannels() []chan *bpf.AgentConnEvtT {
	var channels []chan *bpf.AgentConnEvtT = make([]chan *bpf.AgentConnEvtT, 0)
	for _, each := range pm.processors {
		channels = append(channels, each.connEvents)
	}
	return channels
}
func (pm *ProcessorManager) GetKernEventsChannels() []chan *bpf.AgentKernEvt {
	var channels []chan *bpf.AgentKernEvt = make([]chan *bpf.AgentKernEvt, 0)
	for _, each := range pm.processors {
		channels = append(channels, each.kernEvents)
	}
	return channels
}
func (pm *ProcessorManager) GetFirstPacketEventsChannels() []chan *agentKernEvtWithConn {
	var channels []chan *agentKernEvtWithConn = make([]chan *agentKernEvtWithConn, 0)
	for _, each := range pm.processors {
		channels = append(channels, each.firstPacketsEvents)
	}
	return channels
}

func (pm *ProcessorManager) StopAll() error {
	pm.cancel()
	pm.wg.Wait()
	common.DefaultLog.Debugln("All Processor Stopped.")
	return nil
}

type Processor struct {
	wg                 *sync.WaitGroup
	ctx                context.Context
	connManager        *ConnManager
	connEvents         chan *bpf.AgentConnEvtT
	syscallEvents      chan *bpf.SyscallEventData
	sslEvents          chan *bpf.SslData
	kernEvents         chan *bpf.AgentKernEvt
	firstPacketsEvents chan *agentKernEvtWithConn
	name               string
	messageFilter      protocol.ProtocolFilter
	latencyFilter      protocol.LatencyFilter
	protocol.SizeFilter
	side                        common.SideEnum
	recordProcessor             *RecordsProcessor
	conntrackCloseWaitTimeMills int
	tempKernEvents              *common.RingBuffer
	tempSyscallEvents           *common.RingBuffer
	tempSslEvents               *common.RingBuffer
	tempFirstPacketEvents       *common.RingBuffer
}

type TimedEvent struct {
	event     *bpf.AgentKernEvt
	timestamp time.Time
}

type TimedFirstPacketEvent struct {
	event     *agentKernEvtWithConn
	timestamp time.Time
}

type TimedSyscallEvent struct {
	event     *bpf.SyscallEventData
	timestamp time.Time
}

type TimedSslEvent struct {
	event     *bpf.SslData
	timestamp time.Time
}

func initProcessor(name string, wg *sync.WaitGroup, ctx context.Context, connManager *ConnManager, filter protocol.ProtocolFilter,
	latencyFilter protocol.LatencyFilter, sizeFilter protocol.SizeFilter, side common.SideEnum, conntrackCloseWaitTimeMills int) *Processor {
	p := new(Processor)
	p.wg = wg
	p.ctx = ctx
	p.connManager = connManager
	p.connEvents = make(chan *bpf.AgentConnEvtT)
	p.syscallEvents = make(chan *bpf.SyscallEventData)
	p.sslEvents = make(chan *bpf.SslData)
	p.kernEvents = make(chan *bpf.AgentKernEvt)
	p.firstPacketsEvents = make(chan *agentKernEvtWithConn)
	p.name = name
	p.messageFilter = filter
	p.latencyFilter = latencyFilter
	p.SizeFilter = sizeFilter
	p.side = side
	p.recordProcessor = &RecordsProcessor{
		records: make([]RecordWithConn, 0),
	}
	p.conntrackCloseWaitTimeMills = conntrackCloseWaitTimeMills
	p.tempKernEvents = common.NewRingBuffer(1000)    // Preallocate with a capacity of 100
	p.tempSyscallEvents = common.NewRingBuffer(1000) // Preallocate with a capacity of 100
	p.tempFirstPacketEvents = common.NewRingBuffer(100)
	p.tempSslEvents = common.NewRingBuffer(100) // Preallocate with a capacity of 100
	return p
}

func (p *Processor) AddConnEvent(evt *bpf.AgentConnEvtT) {
	p.connEvents <- evt
}

func (p *Processor) AddSyscallEvent(evt *bpf.SyscallEventData) {
	p.syscallEvents <- evt
}

func (p *Processor) AddSslEvent(evt *bpf.SslData) {
	p.sslEvents <- evt
}

func (p *Processor) AddKernEvent(record *bpf.AgentKernEvt) {
	p.kernEvents <- record
}
func (p *Processor) run() {
	recordChannel := make(chan RecordWithConn)
	go p.recordProcessor.Run(recordChannel, time.NewTicker(1*time.Second))

	// Timer to process kern, syscall, and ssl events
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			common.DefaultLog.Debugf("[%s] stopped", p.name)
			p.wg.Done()
			return
		case event := <-p.connEvents:
			TgidFd := uint64(event.ConnInfo.ConnId.Upid.Pid)<<32 | uint64(event.ConnInfo.ConnId.Fd)
			var conn *Connection4
			isIpv6 := event.ConnInfo.Laddr.In6.Sin6Family == common.AF_INET6
			if isIpv6 {
				common.ConntrackLog.Debugf("ipv6: %x", event.ConnInfo.Laddr.In6.Sin6Addr.In6U.U6Addr8[:])
			}
			if event.ConnType == bpf.AgentConnTypeTKConnect {
				conn = NewConnFromEvent(event, p)
				p.connManager.AddConnection4(TgidFd, conn)
				// if p.side != common.AllSide && p.side != conn.Side() {
				// 	// conn.OnClose(true)
				// 	conn.UpdateConnectionTraceable(false)
				// 	continue
				// }
			} else if event.ConnType == bpf.AgentConnTypeTKClose {
				conn = p.connManager.FindConnection4Exactly(TgidFd)
				if conn == nil {
					continue
				} else {
					conn.CloseTs = event.Ts + common.LaunchEpochTime
				}
				go func(c *Connection4) {
					time.Sleep(time.Duration(p.conntrackCloseWaitTimeMills) * time.Millisecond)
					c.OnClose(true)
				}(conn)
			} else if event.ConnType == bpf.AgentConnTypeTKProtocolInfer {
				// 协议推断
				conn = p.connManager.LookupConnection4ByTimestamp(TgidFd, event.Ts+common.LaunchEpochTime)
				// previousProtocol := conn.Protocol
				if conn != nil && conn.Status != Closed {
					conn.Protocol = event.ConnInfo.Protocol
					common.ConntrackLog.Debugf("[protocol-infer][%s] protocol updated: %d", conn.ToString(), conn.Protocol)
				} else {
					if conn == nil {
						missedConn := NewConnFromEvent(event, p)
						if common.ConntrackLog.Level >= logrus.DebugLevel {
							common.ConntrackLog.Debugf("[no conn][%s]no conn found for infer event", missedConn.ToString())
						}
						p.connManager.AddConnection4(TgidFd, missedConn)
						conn = missedConn
					} else {
						common.ConntrackLog.Debugf("[protocol-infer][%s] protocol not updated: %d", conn.ToString(), conn.Protocol)
						continue
					}
				}

				if conn.Role == bpf.AgentEndpointRoleTKRoleUnknown && event.ConnInfo.Role != bpf.AgentEndpointRoleTKRoleUnknown {
					conn.Role = event.ConnInfo.Role
					onRoleChanged(p, conn)
				}

				isProtocolInterested := conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset ||
					conn.MessageFilter.FilterByProtocol(conn.Protocol)

				if isProtocolInterested && !isSideNotMatched(p, conn) {
					if conn.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown {
						for _, sysEvent := range conn.TempSyscallEvents {
							if conn.timeBoundCheck(sysEvent.SyscallEvent.GetEndTs()) {
								if common.ConntrackLog.Level >= logrus.DebugLevel {
									common.ConntrackLog.Debugf("%s process %d temp syscall events before infer\n", conn.ToString(), len(conn.TempSyscallEvents))
								}
								conn.OnSyscallEvent(sysEvent.Buf, sysEvent, recordChannel)
							}
						}
						conn.TempSyscallEvents = conn.TempSyscallEvents[0:0]
						for _, sslEvent := range conn.TempSslEvents {
							if conn.timeBoundCheck(sslEvent.SslEventHeader.GetEndTs()) {
								if common.ConntrackLog.Level >= logrus.DebugLevel {
									common.ConntrackLog.Debugf("%s process %d temp ssl events before infer\n", conn.ToString(), len(conn.TempSslEvents))
								}
								conn.OnSslDataEvent(sslEvent.Buf, sslEvent, recordChannel)
							}
						}
						conn.TempSslEvents = conn.TempSslEvents[0:0]
						conn.UpdateConnectionTraceable(bpf.AgentConnTraceStateTTraceable)
						// handle kern events
						for _, kernEvent := range conn.TempKernEvents {
							if conn.timeBoundCheck(kernEvent.Ts) {
								if common.ConntrackLog.Level >= logrus.DebugLevel {
									common.ConntrackLog.Debugf("%s process %d temp kern events before infer\n", conn.ToString(), len(conn.TempKernEvents))
								}
								conn.OnKernEvent(kernEvent)
							}
						}
						conn.TempKernEvents = conn.TempKernEvents[0:0]
					}
					conn.TempConnEvents = conn.TempConnEvents[0:0]
				} else {
					if common.ConntrackLog.Level >= logrus.DebugLevel {
						common.ConntrackLog.Debugf("%s discarded due to not interested, isProtocolInterested: %v, isSideNotMatched:%v", conn.ToString(), isProtocolInterested, isSideNotMatched(p, conn))
					}
					if conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnknown {
						conn.UpdateConnectionTraceable(bpf.AgentConnTraceStateTProtocolUnknown)
					} else if !isProtocolInterested {
						conn.UpdateConnectionTraceable(bpf.AgentConnTraceStateTProtocolNotMatched)
					} else {
						conn.UpdateConnectionTraceable(bpf.AgentConnTraceStateTOther)
					}
					// conn.OnClose(true)
				}
			}
			eventType := "connect"
			event.Ts += common.LaunchEpochTime
			if event.ConnType == bpf.AgentConnTypeTKClose {
				eventType = "close"
			} else if event.ConnType == bpf.AgentConnTypeTKProtocolInfer {
				eventType = "infer"
			} else if event.ConnType == bpf.AgentConnTypeTKConnect {
				conn.AddConnEvent(event)
			}

			if common.ConntrackLog.Level >= logrus.DebugLevel {
				common.ConntrackLog.Debugf("[conn][ts=%d] %s | type: %s, protocol: %d, role: %v\n", event.Ts, conn.ToString(), eventType, conn.Protocol, event.ConnInfo.Role)
			}
		case event := <-p.syscallEvents:
			p.handleSyscallEvent(event, recordChannel)
		case event := <-p.sslEvents:
			p.handleSslEvent(event, recordChannel)
		case event := <-p.kernEvents:
			p.handleKernEvent(event, recordChannel)
		case event := <-p.firstPacketsEvents:
			p.handleFirstPacketEvent(event, recordChannel)
		case <-ticker.C:
			p.processTimedSslEvents(recordChannel)
			p.processTimedKernEvents(recordChannel)
			p.processOldFirstPacketEvents(recordChannel)
			p.processTimedSyscallEvents(recordChannel)
		}
	}
}

func (p *Processor) handleFirstPacketEvent(event *agentKernEvtWithConn, recordChannel chan RecordWithConn) {
	// Add event to the temporary queue
	p.tempFirstPacketEvents.Write(TimedFirstPacketEvent{event: event, timestamp: time.Now()})
	// Process events in the queue that have been there for more than 100ms
	p.processOldFirstPacketEvents(recordChannel)
}

func (p *Processor) processTimedFirstPacketEvents(recordChannel chan RecordWithConn) {
	p.processOldFirstPacketEvents(recordChannel)
}

func (p *Processor) processOldFirstPacketEvents(recordChannel chan RecordWithConn) {
	now := time.Now()
	for !p.tempFirstPacketEvents.IsEmpty() {
		_event, err := p.tempFirstPacketEvents.Peek()
		if err != nil {
			break
		}
		event := _event.(TimedFirstPacketEvent)
		if now.Sub(event.timestamp) > 100*time.Millisecond {
			p.processFirstPacketEvent(event.event, recordChannel)
			p.tempFirstPacketEvents.Read()
		} else {
			break
		}
	}
}

func (p *Processor) processFirstPacketEvent(event *agentKernEvtWithConn, recordChannel chan RecordWithConn) {
	// log
	event.Ts += common.LaunchEpochTime
	common.BPFEventLog.Debugf("[first-packet]%s", FormatKernEvt(event.AgentKernEvt, event.Connection4))
	event.Connection4.OnKernEvent(event.AgentKernEvt)
}

func (p *Processor) handleKernEvent(event *bpf.AgentKernEvt, recordChannel chan RecordWithConn) {
	// Add event to the temporary queue
	p.tempKernEvents.Write(TimedEvent{event: event, timestamp: time.Now()})

	// Process events in the queue that have been there for more than 100ms
	p.processOldKernEvents(recordChannel)
}

func (p *Processor) processTimedKernEvents(recordChannel chan RecordWithConn) {
	p.processOldKernEvents(recordChannel)
}

func (p *Processor) processOldKernEvents(recordChannel chan RecordWithConn) {
	now := time.Now()
	for !p.tempKernEvents.IsEmpty() {
		_event, err := p.tempKernEvents.Peek()
		if err != nil {
			break
		}
		event := _event.(TimedEvent)
		if now.Sub(event.timestamp) > 100*time.Millisecond {
			p.processKernEvent(event.event, recordChannel)
			p.tempKernEvents.Read()
		} else {
			break
		}
	}
}

func (p *Processor) processKernEvent(event *bpf.AgentKernEvt, recordChannel chan RecordWithConn) {
	tgidFd := event.ConnIdS.TgidFd
	event.Ts += common.LaunchEpochTime
	conn := p.connManager.LookupConnection4ByTimestamp(tgidFd, event.Ts)

	if conn == nil {
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[no conn]%s", FormatKernEvt(event, conn))
		}
		return
	}
	if !conn.IsTraceble() {
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[no-trace]%s", FormatKernEvt(event, conn))
		}
		return
	}

	if event.Len > 0 && conn.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown {
		if conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset {
			added := conn.OnKernEvent(event)

			if added {
				if common.BPFEventLog.Level >= logrus.DebugLevel {
					common.BPFEventLog.Debugf("[protocol-unset]%s", FormatKernEvt(event, conn))
				}
			} else {
				conn.AddKernEvent(event)
			}

		} else if conn.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown {
			if common.BPFEventLog.Level >= logrus.DebugLevel {
				common.BPFEventLog.Debugf("%s", FormatKernEvt(event, conn))
			}
			conn.OnKernEvent(event)
		}
	} else if event.Len > 0 {
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[protocol-unknown]%s\n", FormatKernEvt(event, conn))
		}
	} else if event.Len == 0 {
		conn.OnKernEvent(event)
	} else {
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[other]%s\n", FormatKernEvt(event, conn))
		}
	}
}

func (p *Processor) handleSyscallEvent(event *bpf.SyscallEventData, recordChannel chan RecordWithConn) {
	// Add event to the temporary queue
	p.tempSyscallEvents.Write(TimedSyscallEvent{event: event, timestamp: time.Now()})

	// Process events in the queue that have been there for more than 100ms
	p.processOldSyscallEvents(recordChannel)
	// p.processSyscallEvent(event, recordChannel)
}

func (p *Processor) processTimedSyscallEvents(recordChannel chan RecordWithConn) {
	p.processOldSyscallEvents(recordChannel)
}

func (p *Processor) processOldSyscallEvents(recordChannel chan RecordWithConn) {
	now := time.Now()
	for !p.tempSyscallEvents.IsEmpty() {
		_event, err := p.tempSyscallEvents.Peek()
		if err != nil {
			break
		}
		event := _event.(TimedSyscallEvent)
		if now.Sub(event.timestamp) > 100*time.Millisecond {
			p.processSyscallEvent(event.event, recordChannel)
			p.tempSyscallEvents.Read()
		} else {
			break
		}
	}
}

func (p *Processor) processSyscallEvent(event *bpf.SyscallEventData, recordChannel chan RecordWithConn) {
	tgidFd := event.SyscallEvent.Ke.ConnIdS.TgidFd
	event.SyscallEvent.Ke.Ts += common.LaunchEpochTime
	conn := p.connManager.LookupConnection4ByTimestamp(tgidFd, event.SyscallEvent.GetEndTs())

	timeCheck := conn != nil && conn.timeBoundCheck(event.SyscallEvent.GetEndTs())
	if conn == nil {
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[syscall][no conn][ts=%d][tgid=%d fd=%d][len=%d] %s", event.SyscallEvent.Ke.Ts, tgidFd>>32, uint32(tgidFd), event.SyscallEvent.BufSize, string(event.Buf))
		}
		return
	}
	if !conn.IsTraceble() {
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[syscall][no-trace][len=%d][ts=%d]%s | %s", event.SyscallEvent.BufSize, event.SyscallEvent.Ke.Ts, conn.ToString(), string(event.Buf))
		}
		return
	}
	if conn.ProtocolInferred() && timeCheck {
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[syscall][len=%d][ts=%d][fn=%d]%s | %s", max(event.SyscallEvent.BufSize, event.SyscallEvent.Ke.Len), event.SyscallEvent.Ke.Ts, event.SyscallEvent.GetSourceFunction(), conn.ToString(), string(event.Buf))
		}

		conn.OnSyscallEvent(event.Buf, event, recordChannel)
	} else if conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset {
		conn.AddSyscallEvent(event)
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[syscall][protocol unset][ts=%d][len=%d]%s | %s", event.SyscallEvent.Ke.Ts, event.SyscallEvent.BufSize, conn.ToString(), string(event.Buf))
		}

	} else if conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnknown {
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[syscall][protocol unknown][ts=%d][len=%d]%s | %s", event.SyscallEvent.Ke.Ts, event.SyscallEvent.BufSize, conn.ToString(), string(event.Buf))
		}
	} else {
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[syscall][other][ts=%d][fn=%d][tgid=%d fd=%d][len=%d] %s", event.SyscallEvent.Ke.Ts, event.SyscallEvent.GetSourceFunction(), tgidFd>>32, uint32(tgidFd), event.SyscallEvent.BufSize, string(event.Buf))
		}
	}
}

func (p *Processor) handleSslEvent(event *bpf.SslData, recordChannel chan RecordWithConn) {
	// Add event to the temporary queue
	p.tempSslEvents.Write(TimedSslEvent{event: event, timestamp: time.Now()})

	// Process events in the queue that have been there for more than 100ms
	p.processOldSslEvents(recordChannel)
}

func (p *Processor) processTimedSslEvents(recordChannel chan RecordWithConn) {
	p.processOldSslEvents(recordChannel)
}

func (p *Processor) processOldSslEvents(recordChannel chan RecordWithConn) {
	now := time.Now()
	for !p.tempSslEvents.IsEmpty() {
		_event, err := p.tempSslEvents.Peek()
		if err != nil {
			break
		}
		event := _event.(TimedSslEvent)
		if now.Sub(event.timestamp) > 100*time.Millisecond {
			p.processSslEvent(event.event, recordChannel)
			p.tempSslEvents.Read()
		} else {
			break
		}
	}
}

func (p *Processor) processSslEvent(event *bpf.SslData, recordChannel chan RecordWithConn) {
	tgidFd := event.SslEventHeader.Ke.ConnIdS.TgidFd
	event.SslEventHeader.Ke.Ts += common.LaunchEpochTime
	conn := p.connManager.LookupConnection4ByTimestamp(tgidFd, event.SslEventHeader.GetEndTs())
	if conn == nil {
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[ssl][no conn][tgid=%d fd=%d][len=%d] %s", tgidFd>>32, uint32(tgidFd), event.SslEventHeader.BufSize, string(event.Buf))
		}
		return
	}
	if !conn.IsTraceble() {
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[ssl][no-trace][len=%d][ts=%d]%s | %s", event.SslEventHeader.BufSize, event.SslEventHeader.Ke.Ts, conn.ToString(), string(event.Buf))
		}
		return
	}

	if conn.ProtocolInferred() {
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[ssl][len=%d][ts=%d]%s | %s", event.SslEventHeader.BufSize, event.SslEventHeader.Ke.Ts, conn.ToString(), string(event.Buf))
		}

		conn.OnSslDataEvent(event.Buf, event, recordChannel)
	} else if conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset {
		conn.AddSslEvent(event)
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[ssl][protocol unset][len=%d]%s | %s", event.SslEventHeader.BufSize, conn.ToString(), string(event.Buf))
		}
	} else if conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnknown {
		conn.AddSslEvent(event)
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[ssl][protocol unknown][len=%d]%s | %s", event.SslEventHeader.BufSize, conn.ToString(), string(event.Buf))
		}
	} else {
		if common.BPFEventLog.Level >= logrus.DebugLevel {
			common.BPFEventLog.Debugf("[ssl][no conn][tgid=%d fd=%d][len=%d] %s", tgidFd>>32, uint32(tgidFd), event.SslEventHeader.BufSize, string(event.Buf))
		}
	}
}

func isSideNotMatched(p *Processor, conn *Connection4) bool {
	return (p.side != common.AllSide) && ((conn.Role == bpf.AgentEndpointRoleTKRoleClient) != (p.side == common.ClientSide))
}
func onRoleChanged(p *Processor, conn *Connection4) {
	if isSideNotMatched(p, conn) {
		if common.ConntrackLog.Level >= logrus.DebugLevel {
			common.ConntrackLog.Debugf("[onRoleChanged] %s discarded due to not matched by side", conn.ToString())
		}
		conn.UpdateConnectionTraceable(bpf.AgentConnTraceStateTOther)
	} else {
		if common.ConntrackLog.Level >= logrus.DebugLevel {
			common.ConntrackLog.Debugf("[onRoleChanged] %s actived due to matched by side", conn.ToString())
		}
		conn.UpdateConnectionTraceable(bpf.AgentConnTraceStateTTraceable)
	}
}

func FormatKernEvt(evt *bpf.AgentKernEvt, conn *Connection4) string {
	var interfaceStr string
	if evt.Ifindex != 0 {
		name, err := getInterfaceNameByIndex(int(evt.Ifindex), int(evt.ConnIdS.TgidFd>>32))
		if err != nil {
			interfaceStr = fmt.Sprintf("[if=%d]", evt.Ifindex)
		} else {
			interfaceStr = fmt.Sprintf("[if=%s]", name)
		}
	}
	if conn != nil {
		return fmt.Sprintf("[kern][ts=%d]%s[%s]%s | %d|%d flags:%s\n", evt.Ts, interfaceStr, bpf.StepCNNames[evt.Step], conn.ToString(), evt.Seq, evt.Len, common.DisplayTcpFlags(evt.Flags))
	} else {
		return fmt.Sprintf("[kern][ts=%d]%s[%s] | %d|%d flags:%s\n", evt.Ts, interfaceStr, bpf.StepCNNames[evt.Step], evt.Seq, evt.Len, common.DisplayTcpFlags(evt.Flags))
	}
}
