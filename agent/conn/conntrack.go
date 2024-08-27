package conn

import (
	"fmt"
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/filter"
	"kyanos/agent/protocol/parser"
	"kyanos/bpf"
	"kyanos/common"
	"sync"
)

var RecordFunc func(protocol.Record, *Connection4) error
var OnCloseRecordFunc func(*Connection4) error

type TCPHandshakeStatus struct {
	ConnectStartTs      uint64 // connect syscall 开始的时间
	ServerSynReceived   bool
	ServerSynReceivedTs uint64
	ClientAckSent       bool
	ClientAckSentTs     uint64
}
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
	TCPHandshakeStatus
	MessageFilter filter.MessageFilter
	filter.LatencyFilter
	filter.SizeFilter
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

func (c *Connection4) submitRecord(record protocol.Record) {
	var err error
	var needSubmit bool

	needSubmit = c.MessageFilter.FilterByProtocol(c.Protocol)
	needSubmit = needSubmit && c.LatencyFilter.Filter(float64(record.Duration)/1000000)
	needSubmit = needSubmit &&
		c.SizeFilter.FilterByReqSize(int64(record.Request.TotalBytes())) &&
		c.SizeFilter.FilterByRespSize(record.Response.TotalBytes())
	if parser := parser.GetParserByProtocol(c.Protocol); needSubmit && parser != nil {
		var parsedRequest, parsedResponse any
		if c.MessageFilter.FilterByRequest() {
			parsedRequest, err = parser.Parse(record.Request)
			if err != nil {
				log.Warnf("%s Fail to parse request when submit record!\n", c.ToString())
				return
			}
		}
		if c.MessageFilter.FilterByResponse() {
			parsedResponse, err = parser.Parse(record.Response)
			if err != nil {
				log.Warnf("%s Fail to parse response when submit record!\n", c.ToString())
				return
			}
		}
		if parsedRequest != nil || parsedResponse != nil {
			needSubmit = c.MessageFilter.Filter(parsedRequest, parsedResponse)
		} else {
			needSubmit = true
		}

	} else {
		needSubmit = false
		// log.Warnf("%s no protocol parser found!\n", c.ToString())
	}
	if needSubmit {
		RecordFunc(record, c)
	}

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
		c.submitRecord(record)
	}
	OnCloseRecordFunc(c)
	c.Status = Closed
}

func (c *Connection4) OnSyscallEvent(data []byte, event *bpf.SyscallEventData) {
	isReq := isReq(c, &event.SyscallEvent.Ke)
	// 以下只能作用于单发单收（一个syscall不包含多个消息，且客户端在接收请求的响应之前不能再发送请求）
	if isReq {
		// 首先要尝试匹配之前的req和resp
		if c.CurResp.HasData() && c.CurReq.HasData() {
			// 匹配 输出record
			record := protocol.Record{
				Request:  c.CurReq,
				Response: c.CurResp,
				Duration: c.CurResp.EndTs - c.CurReq.StartTs,
			}
			c.submitRecord(record)
			// 然后再更新状态
			c.CurReq = protocol.InitProtocolMessage(true, c.IsServerSide())
			c.CurResp = protocol.InitProtocolMessage(false, c.IsServerSide())
		}
		if c.CurReq.HasData() {
			c.CurReq.AppendData(data)
		} else {
			tempReq := c.CurReq
			c.CurReq = protocol.InitProtocolMessageWithEvent(event, isReq, c.IsServerSide())
			c.CurResp = protocol.InitProtocolMessage(false, c.IsServerSide())
			if tempReq.HasEvent() {
				c.CurReq.CopyTimeDetailFrom(tempReq)
			}
			if c.IsServerSide() {
				c.CurReq.AddTimeDetail(bpf.AgentStepTSYSCALL_IN, event.SyscallEvent.Ke.Ts)
			} else {
				c.CurReq.AddTimeDetail(bpf.AgentStepTSYSCALL_OUT, event.SyscallEvent.Ke.Ts)
			}
		}
		c.CurReq.IncrSyscallCount()
		c.CurReq.IncrTotalBytesBy(uint(event.SyscallEvent.Ke.Len))
	} else {
		if c.CurResp.HasData() {
			c.CurResp.AppendData(data)
		} else {
			tempResp := c.CurResp
			c.CurResp = protocol.InitProtocolMessageWithEvent(event, isReq, c.IsServerSide())
			if tempResp.HasEvent() {
				c.CurResp.CopyTimeDetailFrom(tempResp)
			}
			if c.IsServerSide() {
				c.CurResp.AddTimeDetail(bpf.AgentStepTSYSCALL_OUT, event.SyscallEvent.Ke.Ts)
			} else {
				c.CurResp.AddTimeDetail(bpf.AgentStepTSYSCALL_IN, event.SyscallEvent.Ke.Ts)
			}
		}
		c.CurResp.IncrSyscallCount()
		c.CurResp.IncrTotalBytesBy(uint(event.SyscallEvent.Ke.Len))
	}
}

func (c *Connection4) OnKernEvent(event *bpf.AgentKernEvt) bool {
	isReq := isReq(c, event)
	if event.Len > 0 {
		if isReq && c.CurReq != nil {
			c.CurReq.AddTimeDetail(event.Step, event.Ts)
		} else if !isReq && c.CurResp != nil {
			c.CurResp.AddTimeDetail(event.Step, event.Ts)
		} else {
			return false
		}
	} else {
		if (event.Flags&uint8(common.TCP_FLAGS_SYN) != 0) && !isReq && event.Step == bpf.AgentStepTIP_IN {
			// 接收到Server给的Syn包
			if c.ServerSynReceived {
				log.Debugf("[kern][handshake]%s already received server sync, but now received again!\n", c.ToString())
			} else {
				c.ServerSynReceived = true
				c.ServerSynReceivedTs = event.Ts
				log.Debugf("[kern][handshake]%s received server sync\n", c.ToString())
			}
		}
		if (event.Flags&uint8(common.TCP_FLAGS_ACK) != 0) && isReq && c.ServerSynReceived && !c.ClientAckSent && event.Step == bpf.AgentStepTIP_OUT {
			c.ClientAckSent = true
			c.ClientAckSentTs = event.Ts
			log.Debugf("[kern][handshake]%s sent ack, complete handshake, use time: %d(%d-%d)\n", c.ToString(), c.ClientAckSentTs-c.ConnectStartTs, c.ClientAckSentTs, c.ConnectStartTs)
		}
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
	return fmt.Sprintf("[tgid=%d fd=%d][protocol=%d] *%s:%d %s %s:%d", c.TgidFd>>32, uint32(c.TgidFd), c.Protocol, common.IntToIP(c.LocalIp), c.LocalPort, direct, common.IntToIP(c.RemoteIp), c.RemotePort)
}
