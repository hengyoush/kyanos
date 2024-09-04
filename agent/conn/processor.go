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
	latencyFilter protocol.LatencyFilter, sizeFilter protocol.SizeFilter) *ProcessorManager {
	pm := new(ProcessorManager)
	pm.processors = make([]*Processor, n)
	pm.wg = new(sync.WaitGroup)
	pm.ctx, pm.cancel = context.WithCancel(context.Background())
	pm.connManager = connManager
	for i := 0; i < n; i++ {
		pm.processors[i] = initProcessor("Processor-"+fmt.Sprint(i), pm.wg, pm.ctx, pm.connManager, filter, latencyFilter, sizeFilter)
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
}

func initProcessor(name string, wg *sync.WaitGroup, ctx context.Context, connManager *ConnManager, filter protocol.ProtocolFilter,
	latencyFilter protocol.LatencyFilter, sizeFilter protocol.SizeFilter) *Processor {
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
					LocalIp:    event.ConnInfo.Laddr.In4.SinAddr.S_addr,
					RemoteIp:   event.ConnInfo.Raddr.In4.SinAddr.S_addr,
					LocalPort:  event.ConnInfo.Laddr.In4.SinPort,
					RemotePort: event.ConnInfo.Raddr.In4.SinPort,
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
					StreamEvents:     NewKernEventStream(nil),
					prevConn:         []*Connection4{},

					protocolParsers: make(map[bpf.AgentTrafficProtocolT]protocol.ProtocolStreamParser),
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
					c.OnClose()
				}(conn)
			} else if event.ConnType == bpf.AgentConnTypeTKProtocolInfer {
				// 协议推断
				conn = p.connManager.FindConnection4Or(TgidFd, event.Ts+common.LaunchEpochTime)
				if conn != nil && conn.Status != Closed {
					conn.Protocol = event.ConnInfo.Protocol
				} else {
					continue
				}
				if conn.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown {
					// ReportDataEvents(conn.TempKernEvents, conn)
					// ReportConnEvents(conn.TempConnEvents)
					for _, sysEvent := range conn.TempSyscallEvents {
						log.Debugf("%s process temp syscall events before infer\n", conn.ToString())
						conn.OnSyscallEvent(sysEvent.Buf, sysEvent)
					}
				}
				conn.TempKernEvents = conn.TempKernEvents[0:0]
				conn.TempConnEvents = conn.TempConnEvents[0:0]
			}
			direct := "=>"
			if event.ConnInfo.Role != bpf.AgentEndpointRoleTKRoleClient {
				direct = "<="
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
				log.Debugf("[conn][tgid=%d fd=%d] %s:%d %s %s:%d | type: %s, protocol: %d, \n", event.ConnInfo.ConnId.Upid.Pid, event.ConnInfo.ConnId.Fd, common.IntToIP(conn.LocalIp), conn.LocalPort, direct, common.IntToIP(conn.RemoteIp), conn.RemotePort, eventType, conn.Protocol)
			} else {
				log.Debugf("[conn][tgid=%d fd=%d] %s:%d %s %s:%d | type: %s, protocol: %d, \n", event.ConnInfo.ConnId.Upid.Pid, event.ConnInfo.ConnId.Fd, common.IntToIP(conn.LocalIp), conn.LocalPort, direct, common.IntToIP(conn.RemoteIp), conn.RemotePort, eventType, conn.Protocol)
			}
		case event := <-p.syscallEvents:
			tgidFd := event.SyscallEvent.Ke.ConnIdS.TgidFd
			conn := p.connManager.FindConnection4Or(tgidFd, event.SyscallEvent.Ke.Ts+common.LaunchEpochTime)
			event.SyscallEvent.Ke.Ts += common.LaunchEpochTime
			direct := "=>"
			if event.SyscallEvent.Ke.ConnIdS.Direct == bpf.AgentTrafficDirectionTKIngress {
				direct = "<="
			}
			if conn != nil && conn.ProtocolInferred() {
				log.Debugf("[syscall][tgid=%d fd=%d][protocol=%d][len=%d] %s:%d %s %s:%d | %s", tgidFd>>32, uint32(tgidFd), conn.Protocol, event.SyscallEvent.BufSize, common.IntToIP(conn.LocalIp), conn.LocalPort, direct, common.IntToIP(conn.RemoteIp), conn.RemotePort, string(event.Buf))

				conn.OnSyscallEvent(event.Buf, event)
			} else if conn != nil && conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset {
				conn.AddSyscallEvent(event)
				log.Debugf("[syscall][protocol unset][tgid=%d fd=%d][protocol=%d][len=%d] %s:%d %s %s:%d | %s", tgidFd>>32, uint32(tgidFd), conn.Protocol, event.SyscallEvent.BufSize, common.IntToIP(conn.LocalIp), conn.LocalPort, direct, common.IntToIP(conn.RemoteIp), conn.RemotePort, string(event.Buf))
			} else {
				log.Debugf("[syscall][lost][tgid=%d fd=%d][len=%d] %s", tgidFd>>32, uint32(tgidFd), event.SyscallEvent.BufSize, string(event.Buf))
			}
		case event := <-p.kernEvents:
			tgidFd := event.ConnIdS.TgidFd
			conn := p.connManager.FindConnection4Or(tgidFd, event.Ts+common.LaunchEpochTime)
			event.Ts += common.LaunchEpochTime
			direct := "=>"
			if event.ConnIdS.Direct == bpf.AgentTrafficDirectionTKIngress {
				direct = "<="
			}
			if conn != nil {

				log.Debugf("[data][tgid=%d fd=%d][func=%s][ts=%d][%s] *%s:%d %s %s:%d | %d:%d flags:%s\n",
					tgidFd>>32, uint32(event.ConnIdS.TgidFd), common.Int8ToStr(event.FuncName[:]), event.Ts,
					common.StepCNNames[event.Step], common.IntToIP(conn.LocalIp),
					conn.LocalPort, direct, common.IntToIP(conn.RemoteIp), conn.RemotePort, event.Seq, event.Len,
					common.DisplayTcpFlags(event.Flags))

			} else {
				if viper.GetBool(common.VerboseVarName) {
					log.Debugf("[data no conn][tgid=%d fd=%d][func=%s][ts=%d][%s] | %d:%d flags:%s\n",
						tgidFd>>32, uint32(event.ConnIdS.TgidFd), common.Int8ToStr(event.FuncName[:]), event.Ts,
						common.StepCNNames[event.Step], event.Seq, event.Len,
						common.DisplayTcpFlags(event.Flags))
				}
			}
			if event.Len > 0 && conn != nil && conn.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown {
				if conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset {
					conn.OnKernEvent(event)
					// log.Debug("[skip] skip due to protocol unset")
					log.Debugf("[data][protocol-unset][tgid_fd=%d][func=%s][%s] %s:%d %s %s:%d | %d:%d \n", tgidFd, common.Int8ToStr(event.FuncName[:]), common.StepCNNames[event.Step], common.IntToIP(conn.LocalIp), conn.LocalPort, direct, common.IntToIP(conn.RemoteIp), conn.RemotePort, event.Seq, event.Len)
				} else if conn.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown {
					flag := conn.OnKernEvent(event)
					if !flag {
						log.Debug("[skip] skip due to cur req/resp is nil ?(maybe bug)")
					}
				}
			} else if event.Len > 0 && conn != nil {
				log.Debug("[skip] skip due to protocol is unknwon")
				log.Debugf("[data][tgid_fd=%d][func=%s][%s] %s:%d %s %s:%d | %d:%d\n", tgidFd, common.Int8ToStr(event.FuncName[:]), common.StepCNNames[event.Step], common.IntToIP(conn.LocalIp), conn.LocalPort, direct, common.IntToIP(conn.RemoteIp), conn.RemotePort, event.Seq, event.Len)
			} else if event.Len == 0 && conn != nil {
				conn.OnKernEvent(event)
			}
		}
	}
}
