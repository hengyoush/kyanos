package conn

import (
	"eapm-ebpf/agent/protocol"
	"eapm-ebpf/bpf"
	"eapm-ebpf/common"
	"fmt"
	"sync"
)

var RecordFunc func(protocol.Record, *Connection4) error
var OnCloseRecordFunc func(*Connection4) error

type Connection4 struct {
	LocalIp           uint32
	RemoteIp          uint32
	LocalPort         uint16
	RemotePort        uint16
	Protocol          bpf.AgentTrafficProtocolT
	Role              bpf.AgentEndpointRoleT
	TgidFd            uint64
	TempKernEvents    []*bpf.AgentKernEvt
	TempConnEvents    []*bpf.AgentConnEvtT
	TempSyscallEvents []*bpf.SyscallEventData
	Status            ConnStatus
	CurReq            *protocol.BaseProtocolMessage
	CurResp           *protocol.BaseProtocolMessage
}

type ConnStatus uint8

const (
	Connected ConnStatus = 0
	Closed    ConnStatus = 1
)

type ConnManager struct {
	connMap *sync.Map
}

func InitConnManager() *ConnManager {
	return &ConnManager{connMap: new(sync.Map)}
}

func (c *ConnManager) AddConnection4(TgidFd uint64, conn *Connection4) error {
	c.connMap.Store(TgidFd, conn)
	return nil
}

func (c *ConnManager) RemoveConnection4(TgidFd uint64) {
	c.connMap.Delete(TgidFd)
}

func (c *ConnManager) FindConnection4(TgidFd uint64) *Connection4 {
	v, _ := c.connMap.Load(TgidFd)
	if v != nil {
		return v.(*Connection4)
	} else {
		return nil
	}

}

func (c *Connection4) AddKernEvent(e *bpf.AgentKernEvt) {
	c.TempKernEvents = append(c.TempKernEvents, e)
}

func (c *Connection4) AddConnEvent(e *bpf.AgentConnEvtT) {
	c.TempConnEvents = append(c.TempConnEvents, e)
}

func (c *Connection4) AddSyscallEvent(e *bpf.SyscallEventData) {
	c.TempSyscallEvents = append(c.TempSyscallEvents, e)
}

func (c *Connection4) ProtocolInferred() bool {
	return (c.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown) && (c.Protocol != bpf.AgentTrafficProtocolTKProtocolUnset)
}

func (c *Connection4) OnClose() {
	if c.CurResp.HasData() || c.CurReq.HasData() {
		record := protocol.Record{
			Request:  c.CurReq,
			Response: c.CurResp,
		}
		if !c.CurResp.HasData() || !c.CurReq.HasData() {
			// 缺少请求或者响应,连接就关闭了
			record.Duration = 0
		} else {
			record.Duration = c.CurResp.EndTs - c.CurReq.StartTs
		}
		RecordFunc(record, c)
	}
	OnCloseRecordFunc(c)
	c.Status = Closed
}

func (c *Connection4) OnSyscallEvent(data []byte, event *bpf.SyscallEvent) {
	parser := protocol.GetProtocolParser(protocol.ProtocolType(c.Protocol))
	if parser == nil {
		return
	}
	isReq := isReq(c, &event.Ke)
	if isReq {
		// 首先要尝试匹配之前的req和resp
		if c.CurResp.HasData() && c.CurReq.HasData() {
			// 匹配 输出record
			record := protocol.Record{
				Request:  c.CurReq,
				Response: c.CurResp,
				Duration: c.CurResp.EndTs - c.CurReq.StartTs,
			}
			RecordFunc(record, c)
			// 然后再更新状态
			c.CurReq = protocol.InitProtocolMessage(true, c.IsServerSide())
			c.CurResp = protocol.InitProtocolMessage(false, c.IsServerSide())
		}
		if c.CurReq.HasData() {
			c.CurReq.AppendData(data)
		} else {
			tempReq := c.CurReq
			c.CurReq = parser.Parse(event, data, isReq, c.IsServerSide())
			c.CurResp = protocol.InitProtocolMessage(false, c.IsServerSide())
			if tempReq.HasEvent() {
				c.CurReq.CopyTimeDetailFrom(tempReq)
			}
			if c.IsServerSide() {
				c.CurReq.AddTimeDetail(bpf.AgentStepTSYSCALL_IN, event.Ke.Ts)
			} else {
				c.CurReq.AddTimeDetail(bpf.AgentStepTSYSCALL_OUT, event.Ke.Ts)
			}
		}
		c.CurReq.IncrSyscallCount()
		c.CurReq.IncrTotalBytesBy(uint(event.Ke.Len))
	} else {
		if c.CurResp.HasData() {
			c.CurResp.AppendData(data)
		} else {
			tempResp := c.CurResp
			c.CurResp = parser.Parse(event, data, isReq, c.IsServerSide())
			if tempResp.HasEvent() {
				c.CurResp.CopyTimeDetailFrom(tempResp)
			}
			if c.IsServerSide() {
				c.CurResp.AddTimeDetail(bpf.AgentStepTSYSCALL_OUT, event.Ke.Ts)
			} else {
				c.CurResp.AddTimeDetail(bpf.AgentStepTSYSCALL_IN, event.Ke.Ts)
			}
		}
		c.CurResp.IncrSyscallCount()
		c.CurResp.IncrTotalBytesBy(uint(event.Ke.Len))
	}
}

func (c *Connection4) OnKernEvent(event *bpf.AgentKernEvt) bool {
	isReq := isReq(c, event)
	if isReq && c.CurReq != nil {
		c.CurReq.AddTimeDetail(event.Step, event.Ts)
	} else if !isReq && c.CurResp != nil {
		c.CurResp.AddTimeDetail(event.Step, event.Ts)
	} else {
		return false
	}
	return true
}

func isReq(conn *Connection4, event *bpf.AgentKernEvt) bool {
	var isReq bool
	if !conn.IsServerSide() {
		isReq = event.ConnIdS.Direct == bpf.AgentTrafficDirectionTKEgress
	} else {
		isReq = event.ConnIdS.Direct == bpf.AgentTrafficDirectionTKIngress
	}
	return isReq
}

func (c *Connection4) IsServerSide() bool {
	if c.Role == bpf.AgentEndpointRoleTKRoleClient {
		return false
	} else {
		return true
	}
}

func (c *Connection4) ToString() string {
	direct := "=>"
	if c.Role != bpf.AgentEndpointRoleTKRoleClient {
		direct = "<="
	}
	return fmt.Sprintf("[tgidfd=%d][protocol=%d] %s:%d %s %s:%d", c.TgidFd, c.Protocol, common.IntToIP(c.LocalIp), c.LocalPort, direct, common.IntToIP(c.RemoteIp), c.RemotePort)
}
