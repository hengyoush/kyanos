package conn

import (
	"context"
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"
	"sync"
	"time"
)

type ProcessorManager struct {
	processors  []*Processor
	wg          *sync.WaitGroup
	ctx         context.Context
	connManager *ConnManager
	cancel      context.CancelFunc
}

func InitProcessorManager(n int, connManager *ConnManager, filter protocol.ProtocolFilter,
	latencyFilter protocol.LatencyFilter, sizeFilter protocol.SizeFilter, side common.SideEnum) *ProcessorManager {
	pm := new(ProcessorManager)
	pm.processors = make([]*Processor, n)
	pm.wg = new(sync.WaitGroup)
	pm.ctx, pm.cancel = context.WithCancel(context.Background())
	pm.connManager = connManager
	for i := 0; i < n; i++ {
		pm.processors[i] = initProcessor("Processor-"+fmt.Sprint(i), pm.wg, pm.ctx, pm.connManager, filter, latencyFilter, sizeFilter, side)
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

func (pm *ProcessorManager) StopAll() error {
	pm.cancel()
	pm.wg.Wait()
	common.DefaultLog.Debugln("All Processor Stopped!")
	return nil
}

type Processor struct {
	wg            *sync.WaitGroup
	ctx           context.Context
	connManager   *ConnManager
	connEvents    chan *bpf.AgentConnEvtT
	syscallEvents chan *bpf.SyscallEventData
	sslEvents     chan *bpf.SslData
	kernEvents    chan *bpf.AgentKernEvt
	name          string
	messageFilter protocol.ProtocolFilter
	latencyFilter protocol.LatencyFilter
	protocol.SizeFilter
	side            common.SideEnum
	recordProcessor *RecordsProcessor
}

func initProcessor(name string, wg *sync.WaitGroup, ctx context.Context, connManager *ConnManager, filter protocol.ProtocolFilter,
	latencyFilter protocol.LatencyFilter, sizeFilter protocol.SizeFilter, side common.SideEnum) *Processor {
	p := new(Processor)
	p.wg = wg
	p.ctx = ctx
	p.connManager = connManager
	p.connEvents = make(chan *bpf.AgentConnEvtT)
	p.syscallEvents = make(chan *bpf.SyscallEventData)
	p.sslEvents = make(chan *bpf.SslData)
	p.kernEvents = make(chan *bpf.AgentKernEvt)
	p.name = name
	p.messageFilter = filter
	p.latencyFilter = latencyFilter
	p.SizeFilter = sizeFilter
	p.side = side
	p.recordProcessor = &RecordsProcessor{
		records: make([]RecordWithConn, 0),
	}
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
				conn = &Connection4{
					LocalIp: common.BytesToNetIP(event.ConnInfo.Laddr.In6.Sin6Addr.In6U.U6Addr8[:], isIpv6),
					// LocalIp:    common.IntToBytes(event.ConnInfo.Laddr.In4.SinAddr.S_addr),
					RemoteIp: common.BytesToNetIP(event.ConnInfo.Raddr.In6.Sin6Addr.In6U.U6Addr8[:], isIpv6),
					// RemoteIp:   common.IntToBytes(event.ConnInfo.Raddr.In4.SinAddr.S_addr),
					LocalPort:  common.Port(event.ConnInfo.Laddr.In6.Sin6Port),
					RemotePort: common.Port(event.ConnInfo.Raddr.In6.Sin6Port),
					Protocol:   event.ConnInfo.Protocol,
					Role:       event.ConnInfo.Role,
					TgidFd:     TgidFd,
					Status:     Connected,

					MessageFilter: p.messageFilter,
					LatencyFilter: p.latencyFilter,
					SizeFilter:    p.SizeFilter,

					reqStreamBuffer:  buffer.New(1024 * 1024),
					respStreamBuffer: buffer.New(1024 * 1024),
					ReqQueue:         make([]protocol.ParsedMessage, 0),
					RespQueue:        make([]protocol.ParsedMessage, 0),

					prevConn: []*Connection4{},

					protocolParsers: make(map[bpf.AgentTrafficProtocolT]protocol.ProtocolStreamParser),
				}
				conn.StreamEvents = NewKernEventStream(conn, 300)
				if p.side != common.AllSide && p.side != conn.Side() {
					// conn.OnClose(true)
					conn.UpdateConnectionTraceable(false)
					continue
				}
				conn.ConnectStartTs = event.Ts + common.LaunchEpochTime
				p.connManager.AddConnection4(TgidFd, conn)
			} else if event.ConnType == bpf.AgentConnTypeTKClose {
				conn = p.connManager.FindConnection4Exactly(TgidFd)
				if conn == nil {
					continue
				} else {
					conn.CloseTs = event.Ts + common.LaunchEpochTime
				}
				go func(c *Connection4) {
					time.Sleep(1 * time.Second)
					c.OnClose(true)
				}(conn)
			} else if event.ConnType == bpf.AgentConnTypeTKProtocolInfer {
				// 协议推断
				conn = p.connManager.FindConnection4Or(TgidFd, event.Ts+common.LaunchEpochTime)
				// previousProtocol := conn.Protocol
				if conn != nil && conn.Status != Closed {
					conn.Protocol = event.ConnInfo.Protocol
				} else {
					continue
				}

				if conn.Role == bpf.AgentEndpointRoleTKRoleUnknown && event.ConnInfo.Role != bpf.AgentEndpointRoleTKRoleUnknown {
					conn.Role = event.ConnInfo.Role
				}

				isProtocolInterested := conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset ||
					conn.MessageFilter.FilterByProtocol(conn.Protocol)

				if isProtocolInterested {
					if conn.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown {
						for _, sysEvent := range conn.TempSyscallEvents {
							common.BPFEventLog.Debugf("%s process %d temp syscall events before infer\n", conn.ToString(), len(conn.TempSyscallEvents))
							conn.OnSyscallEvent(sysEvent.Buf, sysEvent, recordChannel)
						}
						for _, sslEvent := range conn.TempSslEvents {
							common.BPFEventLog.Debugf("%s process %d temp ssl events before infer\n", conn.ToString(), len(conn.TempSslEvents))
							conn.OnSslDataEvent(sslEvent.Buf, sslEvent, recordChannel)
						}
						conn.UpdateConnectionTraceable(true)
					}
					conn.TempKernEvents = conn.TempKernEvents[0:0]
					conn.TempConnEvents = conn.TempConnEvents[0:0]
				} else {
					common.BPFEventLog.Debugf("%s discarded due to not interested", conn.ToString())
					conn.UpdateConnectionTraceable(false)
					// conn.OnClose(true)
				}
			}
			eventType := "connect"
			event.Ts += common.LaunchEpochTime
			if event.ConnType == bpf.AgentConnTypeTKClose {
				eventType = "close"
			} else if event.ConnType == bpf.AgentConnTypeTKProtocolInfer {
				eventType = "infer"
				// 连接推断事件可以不上报
			} else if event.ConnType == bpf.AgentConnTypeTKConnect {
				conn.AddConnEvent(event)
			}

			if event.ConnType == bpf.AgentConnTypeTKProtocolInfer && conn.ProtocolInferred() {
				common.BPFEventLog.Debugf("[conn] %s | type: %s, protocol: %d, \n", conn.ToString(), eventType, conn.Protocol)
			} else {
				common.BPFEventLog.Debugf("[conn] %s | type: %s, protocol: %d, \n", conn.ToString(), eventType, conn.Protocol)
			}
		case event := <-p.syscallEvents:
			tgidFd := event.SyscallEvent.Ke.ConnIdS.TgidFd
			conn := p.connManager.FindConnection4Or(tgidFd, event.SyscallEvent.Ke.Ts+common.LaunchEpochTime)
			event.SyscallEvent.Ke.Ts += common.LaunchEpochTime
			if conn != nil && conn.Status == Closed {
				continue
			}
			if conn != nil && conn.ProtocolInferred() {
				common.BPFEventLog.Debugf("[syscall][len=%d]%s | %s", event.SyscallEvent.BufSize, conn.ToString(), string(event.Buf))

				conn.OnSyscallEvent(event.Buf, event, recordChannel)
			} else if conn != nil && conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset {
				conn.AddSyscallEvent(event)
				common.BPFEventLog.Debugf("[syscall][protocol unset][len=%d]%s | %s", event.SyscallEvent.BufSize, conn.ToString(), string(event.Buf))
			} else if conn != nil && conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnknown {
				common.BPFEventLog.Debugf("[syscall][protocol unknown][len=%d]%s | %s", event.SyscallEvent.BufSize, conn.ToString(), string(event.Buf))
			} else {
				common.BPFEventLog.Debugf("[syscall][no conn][tgid=%d fd=%d][len=%d] %s", tgidFd>>32, uint32(tgidFd), event.SyscallEvent.BufSize, string(event.Buf))
			}
		case event := <-p.sslEvents:
			tgidFd := event.SslEventHeader.Ke.ConnIdS.TgidFd
			conn := p.connManager.FindConnection4Or(tgidFd, event.SslEventHeader.Ke.Ts+common.LaunchEpochTime)
			event.SslEventHeader.Ke.Ts += common.LaunchEpochTime
			if conn != nil && conn.Status == Closed {
				continue
			}
			if conn != nil && conn.ProtocolInferred() {
				common.BPFEventLog.Debugf("[ssl][len=%d]%s | %s", event.SslEventHeader.BufSize, conn.ToString(), string(event.Buf))

				conn.OnSslDataEvent(event.Buf, event, recordChannel)
			} else if conn != nil && conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset {
				conn.AddSslEvent(event)
				common.BPFEventLog.Debugf("[ssl][protocol unset][len=%d]%s | %s", event.SslEventHeader.BufSize, conn.ToString(), string(event.Buf))
			} else if conn != nil && conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnknown {
				conn.AddSslEvent(event)
				common.BPFEventLog.Debugf("[ssl][protocol unknown][len=%d]%s | %s", event.SslEventHeader.BufSize, conn.ToString(), string(event.Buf))
			} else {
				common.BPFEventLog.Debugf("[ssl][no conn][tgid=%d fd=%d][len=%d] %s", tgidFd>>32, uint32(tgidFd), event.SslEventHeader.BufSize, string(event.Buf))
			}
		case event := <-p.kernEvents:
			tgidFd := event.ConnIdS.TgidFd
			conn := p.connManager.FindConnection4Or(tgidFd, event.Ts+common.LaunchEpochTime)
			event.Ts += common.LaunchEpochTime
			// if conn != nil {
			// 	common.BPFEventLog.Debugf("[data][func=%s][ts=%d][%s]%s | %d:%d flags:%s\n", common.Int8ToStr(event.FuncName[:]), event.Ts, bpf.StepCNNames[event.Step],
			// 		conn.ToString(), event.Seq, event.Len,
			// 		common.DisplayTcpFlags(event.Flags))
			// } else {
			// 	common.BPFEventLog.Debugf("[data no conn][tgid=%d fd=%d][func=%s][ts=%d][%s] | %d:%d flags:%s\n", tgidFd>>32, uint32(tgidFd), common.Int8ToStr(event.FuncName[:]), event.Ts, bpf.StepCNNames[event.Step],
			// 		event.Seq, event.Len,
			// 		common.DisplayTcpFlags(event.Flags))
			// }
			if event.Len > 0 && conn != nil && conn.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown {
				if conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset {
					conn.OnKernEvent(event)
					// log.Debug("[skip] skip due to protocol unset")
					common.BPFEventLog.Debugf("[protocol-unset]%s", FormatKernEvt(event, conn))
				} else if conn.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown {
					common.BPFEventLog.Debugf("%s", FormatKernEvt(event, conn))
					conn.OnKernEvent(event)
				}
			} else if event.Len > 0 && conn != nil {
				common.BPFEventLog.Debugf("[protocol-unknown]%s\n", FormatKernEvt(event, conn))
			} else if event.Len == 0 && conn != nil {
				conn.OnKernEvent(event)
			} else if conn == nil {
				common.BPFEventLog.Debugf("[no-conn]%s\n", FormatKernEvt(event, conn))
			} else {
				common.BPFEventLog.Debugf("[other]%s\n", FormatKernEvt(event, conn))
			}
		}
	}
}

func FormatKernEvt(evt *bpf.AgentKernEvt, conn *Connection4) string {
	var interfaceStr string
	if evt.Ifindex != 0 {
		name, err := common.GetInterfaceNameByIndex(int(evt.Ifindex), int(evt.ConnIdS.TgidFd>>32))
		if err != nil {
			interfaceStr = "[if=unknown]"
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
