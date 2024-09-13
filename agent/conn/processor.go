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

	"github.com/jefurry/logrus"
	"github.com/spf13/viper"
)

var log *logrus.Logger = common.Log

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

func (pm *ProcessorManager) StopAll() error {
	pm.cancel()
	pm.wg.Wait()
	log.Debugln("All Processor Stopped!")
	return nil
}

type Processor struct {
	wg            *sync.WaitGroup
	ctx           context.Context
	connManager   *ConnManager
	connEvents    chan *bpf.AgentConnEvtT
	syscallEvents chan *bpf.SyscallEventData
	kernEvents    chan *bpf.AgentKernEvt
	name          string
	messageFilter protocol.ProtocolFilter
	latencyFilter protocol.LatencyFilter
	protocol.SizeFilter
	side common.SideEnum
}

func initProcessor(name string, wg *sync.WaitGroup, ctx context.Context, connManager *ConnManager, filter protocol.ProtocolFilter,
	latencyFilter protocol.LatencyFilter, sizeFilter protocol.SizeFilter, side common.SideEnum) *Processor {
	p := new(Processor)
	p.wg = wg
	p.ctx = ctx
	p.connManager = connManager
	p.connEvents = make(chan *bpf.AgentConnEvtT)
	p.syscallEvents = make(chan *bpf.SyscallEventData)
	p.kernEvents = make(chan *bpf.AgentKernEvt)
	p.name = name
	p.messageFilter = filter
	p.latencyFilter = latencyFilter
	p.SizeFilter = sizeFilter
	p.side = side
	return p
}

func (p *Processor) AddConnEvent(evt *bpf.AgentConnEvtT) {
	p.connEvents <- evt
}

func (p *Processor) AddSyscallEvent(evt *bpf.SyscallEventData) {
	p.syscallEvents <- evt
}

func (p *Processor) AddKernEvent(record *bpf.AgentKernEvt) {
	p.kernEvents <- record
}
func (p *Processor) run() {
	for {
		select {
		case <-p.ctx.Done():
			common.Log.Debugf("[%s] stopped", p.name)
			p.wg.Done()
			return
		case event := <-p.connEvents:
			TgidFd := uint64(event.ConnInfo.ConnId.Upid.Pid)<<32 | uint64(event.ConnInfo.ConnId.Fd)
			var conn *Connection4
			if event.ConnType == bpf.AgentConnTypeTKConnect {
				conn = &Connection4{
					LocalIp:    common.IntToBytes(event.ConnInfo.Laddr.In4.SinAddr.S_addr),
					RemoteIp:   common.IntToBytes(event.ConnInfo.Raddr.In4.SinAddr.S_addr),
					LocalPort:  common.Port(event.ConnInfo.Laddr.In4.SinPort),
					RemotePort: common.Port(event.ConnInfo.Raddr.In4.SinPort),
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
							log.Debugf("%s process temp syscall events before infer\n", conn.ToString())
							conn.OnSyscallEvent(sysEvent.Buf, sysEvent)
						}
						conn.UpdateConnectionTraceable(true)
					}
					conn.TempKernEvents = conn.TempKernEvents[0:0]
					conn.TempConnEvents = conn.TempConnEvents[0:0]
				} else {
					log.Debugf("%s discarded due to not interested", conn.ToString())
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
				log.Debugf("[conn] %s | type: %s, protocol: %d, \n", conn.ToString(), eventType, conn.Protocol)
			} else {
				log.Debugf("[conn] %s | type: %s, protocol: %d, \n", conn.ToString(), eventType, conn.Protocol)
			}
		case event := <-p.syscallEvents:
			tgidFd := event.SyscallEvent.Ke.ConnIdS.TgidFd
			conn := p.connManager.FindConnection4Or(tgidFd, event.SyscallEvent.Ke.Ts+common.LaunchEpochTime)
			event.SyscallEvent.Ke.Ts += common.LaunchEpochTime
			if conn != nil && conn.Status == Closed {
				continue
			}
			if conn != nil && conn.ProtocolInferred() {
				log.Debugf("[syscall][len=%d]%s | %s", event.SyscallEvent.BufSize, conn.ToString(), string(event.Buf))

				conn.OnSyscallEvent(event.Buf, event)
			} else if conn != nil && conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset {
				conn.AddSyscallEvent(event)
				log.Debugf("[syscall][protocol unset][len=%d]%s | %s", event.SyscallEvent.BufSize, conn.ToString(), string(event.Buf))
			} else {
				log.Debugf("[syscall][lost][tgid=%d fd=%d][len=%d] %s", tgidFd>>32, uint32(tgidFd), event.SyscallEvent.BufSize, string(event.Buf))
			}
		case event := <-p.kernEvents:
			tgidFd := event.ConnIdS.TgidFd
			conn := p.connManager.FindConnection4Or(tgidFd, event.Ts+common.LaunchEpochTime)
			event.Ts += common.LaunchEpochTime
			if conn != nil {
				log.Debugf("[data][func=%s][ts=%d][%s]%s | %d:%d flags:%s\n", common.Int8ToStr(event.FuncName[:]), event.Ts, bpf.StepCNNames[event.Step],
					conn.ToString(), event.Seq, event.Len,
					common.DisplayTcpFlags(event.Flags))

			} else {
				if viper.GetBool(common.VerboseVarName) {
					// log.Debugf("[data no conn][func=%s][ts=%d][%s]%s | %d:%d flags:%s\n", common.Int8ToStr(event.FuncName[:]), event.Ts, common.StepCNNames[event.Step],
					// 	conn.ToString(), event.Seq, event.Len,
					// 	common.DisplayTcpFlags(event.Flags))
				}
			}
			if event.Len > 0 && conn != nil && conn.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown {
				if conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset {
					conn.OnKernEvent(event)
					// log.Debug("[skip] skip due to protocol unset")
					log.Debugf("[data][protocol-unset][func=%s][%s]%s | %d:%d \n", common.Int8ToStr(event.FuncName[:]), bpf.StepCNNames[event.Step], conn.ToString(), event.Seq, event.Len)
				} else if conn.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown {
					flag := conn.OnKernEvent(event)
					if !flag {
						log.Debug("[skip] skip due to cur req/resp is nil ?(maybe bug)")
					}
				}
			} else if event.Len > 0 && conn != nil {
				log.Debug("[skip] skip due to protocol is unknwon")
				log.Debugf("[data][func=%s][%s]%s | %d:%d\n", common.Int8ToStr(event.FuncName[:]), bpf.StepCNNames[event.Step], conn.ToString(), event.Seq, event.Len)
			} else if event.Len == 0 && conn != nil {
				conn.OnKernEvent(event)
			}
		}
	}
}
