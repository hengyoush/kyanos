package conn

import (
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	_ "kyanos/agent/protocol/mysql"
	"kyanos/bpf"
	"kyanos/common"
	"slices"
	"sync"
)

// var RecordFunc func(protocol.Record, *Connection4) error
var RecordFunc func(protocol.Record, *Connection4) error
var OnCloseRecordFunc func(*Connection4) error

type Connection4 struct {
	LocalIp    common.Addr
	RemoteIp   common.Addr
	LocalPort  common.Port
	RemotePort common.Port
	Protocol   bpf.AgentTrafficProtocolT
	Role       bpf.AgentEndpointRoleT
	TgidFd     uint64

	TempKernEvents    []*bpf.AgentKernEvt
	TempConnEvents    []*bpf.AgentConnEvtT
	TempSyscallEvents []*bpf.SyscallEventData
	Status            ConnStatus
	TCPHandshakeStatus

	reqStreamBuffer  *buffer.StreamBuffer
	respStreamBuffer *buffer.StreamBuffer
	ReqQueue         []protocol.ParsedMessage
	RespQueue        []protocol.ParsedMessage
	StreamEvents     *KernEventStream

	MessageFilter protocol.ProtocolFilter
	LatencyFilter protocol.LatencyFilter
	SizeFilter    protocol.SizeFilter

	prevConn        []*Connection4
	protocolParsers map[bpf.AgentTrafficProtocolT]protocol.ProtocolStreamParser
}
type ConnStatus uint8

type TCPHandshakeStatus struct {
	ConnectStartTs      uint64 // connect syscall 开始的时间
	ServerSynReceived   bool
	ServerSynReceivedTs uint64
	ClientAckSent       bool
	ClientAckSentTs     uint64
	CloseTs             uint64
}

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
	existedConn := c.FindConnection4Exactly(TgidFd)
	if existedConn != nil {
		if !existedConn.IsIpPortEqualsWith(conn) {
			prevConn := existedConn.prevConn
			deleteEndIdx := -1
			for idx := len(prevConn) - 1; idx >= 0; idx-- {
				if prevConn[idx].Status == Closed {
					deleteEndIdx = idx
					break
				}
			}
			if deleteEndIdx != -1 {
				prevConn = prevConn[deleteEndIdx+1:]
			}

			prevConn = append(prevConn, existedConn)
			conn.prevConn = prevConn

			c.connMap.Store(TgidFd, conn)
			return nil
		} else {
			return nil
		}
	} else {
		c.connMap.Store(TgidFd, conn)
		return nil
	}

}

func (c *ConnManager) RemoveConnection4(TgidFd uint64) {
	c.connMap.Delete(TgidFd)
}

func (c *ConnManager) FindConnection4Exactly(TgidFd uint64) *Connection4 {
	v, _ := c.connMap.Load(TgidFd)
	if v != nil {
		return v.(*Connection4)
	} else {
		return nil
	}
}

func (c *ConnManager) FindConnection4Or(TgidFd uint64, ts uint64) *Connection4 {
	v, _ := c.connMap.Load(TgidFd)
	connection, _ := v.(*Connection4)
	if connection == nil {
		return nil
	} else {
		if connection.ConnectStartTs < ts {
			return connection
		} else {
			curConnList := connection.prevConn
			if len(curConnList) > 0 {
				lastPrevConn := curConnList[len(curConnList)-1]
				if lastPrevConn.CloseTs != 0 && lastPrevConn.CloseTs < ts {
					return connection
				}
			}
			for idx := len(curConnList) - 1; idx >= 0; idx-- {
				if curConnList[idx].ConnectStartTs < ts {
					return curConnList[idx]
				}
			}
			return nil
		}
	}
}

func (c *Connection4) IsIpPortEqualsWith(o *Connection4) bool {
	return slices.Compare(c.LocalIp, o.LocalIp) == 0 && slices.Compare(c.RemoteIp, o.RemoteIp) == 0 && c.RemotePort == o.RemotePort && c.LocalPort == o.LocalPort
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
	var needSubmit bool

	needSubmit = c.MessageFilter.FilterByProtocol(c.Protocol)
	var duration uint64
	if c.IsServerSide() {
		duration = record.Request().TimestampNs() - record.Response().TimestampNs()
	} else {
		duration = record.Response().TimestampNs() - record.Request().TimestampNs()
	}

	needSubmit = needSubmit && c.LatencyFilter.Filter(float64(duration)/1000000)
	needSubmit = needSubmit &&
		c.SizeFilter.FilterByReqSize(int64(record.Request().ByteSize())) &&
		c.SizeFilter.FilterByRespSize(int64(record.Response().ByteSize()))
	if parser := c.GetProtocolParser(c.Protocol); needSubmit && parser != nil {
		var parsedRequest, parsedResponse protocol.ParsedMessage
		if c.MessageFilter.FilterByRequest() {
			parsedRequest = record.Request()
		}
		if c.MessageFilter.FilterByResponse() {
			parsedResponse = record.Response()
		}
		if parsedRequest != nil || parsedResponse != nil {
			needSubmit = c.MessageFilter.Filter(parsedRequest, parsedResponse)
		} else {
			needSubmit = true
		}

	} else {
		needSubmit = false
	}
	if needSubmit {
		RecordFunc(record, c)
	}
}

func (c *Connection4) OnClose(needClearBpfMap bool) {
	OnCloseRecordFunc(c)
	c.Status = Closed
	if needClearBpfMap {
		connInfoMap := bpf.GetMap("ConnInfoMap")
		err := connInfoMap.Delete(c.TgidFd)
		if err != nil {
			log.Errorf("clean conn_info_map failed: %v", err)
		}
	}
}

func (c *Connection4) OnCloseWithoutClearBpfMap() {
	c.OnClose(false)
}
func (c *Connection4) OnKernEvent(event *bpf.AgentKernEvt) bool {
	isReq := isReq(c, event)
	if event.Len > 0 {
		c.StreamEvents.AddKernEvent(event)
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
func (c *Connection4) OnSyscallEvent(data []byte, event *bpf.SyscallEventData) {
	isReq := isReq(c, &event.SyscallEvent.Ke)
	if isReq {

		c.reqStreamBuffer.Add(event.SyscallEvent.Ke.Seq, data, event.SyscallEvent.Ke.Ts)
	} else {
		c.respStreamBuffer.Add(event.SyscallEvent.Ke.Seq, data, event.SyscallEvent.Ke.Ts)
	}

	c.parseStreamBuffer(c.reqStreamBuffer, protocol.Request, &c.ReqQueue)
	c.parseStreamBuffer(c.respStreamBuffer, protocol.Response, &c.RespQueue)
	c.StreamEvents.AddSyscallEvent(event)

	parser := c.GetProtocolParser(c.Protocol)
	if parser == nil {
		panic("no protocol parser!")
	}

	records := parser.Match(&c.ReqQueue, &c.RespQueue)
	for _, each := range records {
		c.submitRecord(each)
	}
}

func (c *Connection4) parseStreamBuffer(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType, resultQueue *[]protocol.ParsedMessage) {
	parser := c.GetProtocolParser(c.Protocol)
	if parser == nil {
		streamBuffer.Clear()
		return
	}
	if streamBuffer.IsEmpty() {
		return
	}
	stop := false
	startPos := parser.FindBoundary(streamBuffer, messageType, 0)
	if startPos == -1 {
		// TODO
		startPos = 0
	}
	streamBuffer.RemovePrefix(startPos)
	for !stop && !streamBuffer.IsEmpty() {
		parseResult := parser.ParseStream(streamBuffer, messageType)
		switch parseResult.ParseState {
		case protocol.Success:
			*resultQueue = append(*resultQueue, parseResult.ParsedMessages...)
			streamBuffer.RemovePrefix(parseResult.ReadBytes)
		case protocol.Invalid:
			pos := parser.FindBoundary(streamBuffer, messageType, 1)
			if pos != -1 {
				streamBuffer.RemovePrefix(pos)
				stop = false
			} else {
				stop = true
			}
		case protocol.NeedsMoreData:
			stop = true
		case protocol.Ignore:
			stop = false
			streamBuffer.RemovePrefix(parseResult.ReadBytes)
		default:
			panic("invalid parse state!")
		}
	}

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
	return fmt.Sprintf("[tgid=%d fd=%d][protocol=%d] *%s:%d %s %s:%d", c.TgidFd>>32, uint32(c.TgidFd), c.Protocol, c.LocalIp.String(), c.LocalPort, direct, c.RemoteIp.String(), c.RemotePort)
}

func (c *Connection4) GetProtocolParser(p bpf.AgentTrafficProtocolT) protocol.ProtocolStreamParser {
	if parser, ok := c.protocolParsers[p]; ok {
		return parser
	} else {
		parser := protocol.GetParserByProtocol(p)
		c.protocolParsers[p] = parser
		return parser
	}
}
