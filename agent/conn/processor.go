package conn

import (
	"context"
	"eapm-ebpf/bpf"
	"eapm-ebpf/common"
	"fmt"
	"sync"

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

func InitProcessorManager(n int, connManager *ConnManager) *ProcessorManager {
	pm := new(ProcessorManager)
	pm.processors = make([]*Processor, n)
	pm.wg = new(sync.WaitGroup)
	pm.ctx, pm.cancel = context.WithCancel(context.Background())
	pm.connManager = connManager
	for i := 0; i < n; i++ {
		pm.processors[i] = initProcessor("Processor-"+fmt.Sprint(i), pm.wg, pm.ctx, pm.connManager)
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
	log.Infoln("All Processor Stopped!")
	return nil
}

type Processor struct {
	wg            *sync.WaitGroup
	ctx           context.Context
	connManager   *ConnManager
	syscallEvents chan *bpf.SyscallEventData
	kernEvents    chan *bpf.AgentKernEvt
	name          string
}

func initProcessor(name string, wg *sync.WaitGroup, ctx context.Context, connManager *ConnManager) *Processor {
	p := new(Processor)
	p.wg = wg
	p.ctx = ctx
	p.connManager = connManager
	p.syscallEvents = make(chan *bpf.SyscallEventData)
	p.kernEvents = make(chan *bpf.AgentKernEvt)
	p.name = name
	return p
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
			common.Log.Infof("[%s] stopped", p.name)
			p.wg.Done()
			return
		case event := <-p.syscallEvents:
			tgidFd := event.SyscallEvent.Ke.ConnIdS.TgidFd
			conn := p.connManager.FindConnection4(tgidFd)
			event.SyscallEvent.Ke.Ts += common.LaunchEpochTime
			// direct := "=>"
			// if event.Ke.ConnIdS.Direct == bpf.AgentTrafficDirectionTKIngress {
			// 	direct = "<="
			// }
			if conn != nil && conn.ProtocolInferred() {
				// log.Infof("[syscall][tgidfd=%d][protocol=%d] %s:%d %s %s:%d | %s", tgidFd, conn.Protocol, common.IntToIP(conn.LocalIp), conn.LocalPort, direct, common.IntToIP(conn.RemoteIp), conn.RemotePort, string(buf))
				conn.OnSyscallEvent(event.Buf, &event.SyscallEvent)
			} else if conn != nil && conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset {
				conn.AddSyscallEvent(event)
				// log.Infof("[syscall][protocol unset][tgidfd=%d][protocol=%d] %s:%d %s %s:%d | %s", tgidFd, conn.Protocol, common.IntToIP(conn.LocalIp), conn.LocalPort, direct, common.IntToIP(conn.RemoteIp), conn.RemotePort, string(buf))
			}
		case event := <-p.kernEvents:
			tgidFd := event.ConnIdS.TgidFd
			conn := p.connManager.FindConnection4(tgidFd)
			event.Ts += common.LaunchEpochTime
			direct := "=>"
			if event.ConnIdS.Direct == bpf.AgentTrafficDirectionTKIngress {
				direct = "<="
			}
			if conn != nil {
				if viper.GetBool(common.ConsoleOutputVarName) {
					log.Debugf("[data][tgid_fd=%d][func=%s][ts=%d][%s] %s:%d %s %s:%d | %d:%d flags:%s\n",
						tgidFd, common.Int8ToStr(event.FuncName[:]), event.Ts,
						common.StepCNNames[event.Step], common.IntToIP(conn.LocalIp),
						conn.LocalPort, direct, common.IntToIP(conn.RemoteIp), conn.RemotePort, event.Seq, event.Len,
						common.DisplayTcpFlags(event.Flags))
				}

			} else {
				if viper.GetBool(common.ConsoleOutputVarName) {
					log.Debugf("[data no conn][tgid_fd=%d][func=%s][ts=%d][%s] | %d:%d flags:%s\n",
						tgidFd, common.Int8ToStr(event.FuncName[:]), event.Ts,
						common.StepCNNames[event.Step], event.Seq, event.Len,
						common.DisplayTcpFlags(event.Flags))
				}
			}
			if event.Len > 0 && conn != nil && conn.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown {
				if conn.Protocol == bpf.AgentTrafficProtocolTKProtocolUnset {
					// TODO 推断出协议之前的事件需要处理，这里暂时略过
					// conn.AddKernEvent(&event)
					conn.OnKernEvent(event)
					// log.Infof("[skip] skip due to protocol unset")
					// log.Infof("[data][tgid_fd=%d][func=%s][%s] %s:%d %s %s:%d | %d:%d\n", tgidFd, common.Int8ToStr(event.FuncName[:]), common.StepCNNames[event.Step], common.IntToIP(conn.LocalIp), conn.LocalPort, direct, common.IntToIP(conn.RemoteIp), conn.RemotePort, event.Seq, event.Len)
				} else if conn.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown {
					flag := conn.OnKernEvent(event)
					if !flag {
						log.Infof("[skip] skip due to cur req/resp is nil ?(maybe bug)")
					}
				}
			} else if event.Len > 0 && conn != nil {
				log.Infof("[skip] skip due to protocol is unknwon")
				log.Infof("[data][tgid_fd=%d][func=%s][%s] %s:%d %s %s:%d | %d:%d\n", tgidFd, common.Int8ToStr(event.FuncName[:]), common.StepCNNames[event.Step], common.IntToIP(conn.LocalIp), conn.LocalPort, direct, common.IntToIP(conn.RemoteIp), conn.RemotePort, event.Seq, event.Len)
			} else if event.Len == 0 && conn != nil {
				conn.OnKernEvent(event)
			}
		}
	}
}
