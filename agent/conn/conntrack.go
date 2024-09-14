package conn

import (
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	_ "kyanos/agent/protocol/mysql"
	"kyanos/bpf"
	"kyanos/common"
	"kyanos/monitor"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
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

	reqStreamBuffer          *buffer.StreamBuffer
	respStreamBuffer         *buffer.StreamBuffer
	ReqQueue                 []protocol.ParsedMessage
	lastReqMadeProgressTime  int64
	lastRespMadeProgressTime int64
	RespQueue                []protocol.ParsedMessage
	StreamEvents             *KernEventStream

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
	connMap          *sync.Map
	connectionAdded  int64
	connectionClosed int64
	ticker           *time.Ticker
}

func InitConnManager() *ConnManager {
	connManager := &ConnManager{connMap: new(sync.Map)}
	monitor.RegisterMetricExporter(connManager)
	connManager.ticker = time.NewTicker(15 * time.Second)
	go func() {
		for i := range connManager.ticker.C {
			i.GoString()
			_needsDelete := make([]uint64, 0)
			needsDelete := &_needsDelete
			connManager.connMap.Range(func(key, value any) bool {
				conn := value.(*Connection4)
				if conn.Status == Closed {
					*needsDelete = append(*needsDelete, key.(uint64))
				}
				return true
			})
			for _, tgidFd := range _needsDelete {
				connManager.connMap.Delete(tgidFd)
			}
			atomic.AddInt64(&connManager.connectionClosed, int64(len(_needsDelete)))
		}
	}()
	return connManager
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
				atomic.AddInt64(&c.connectionClosed, int64(deleteEndIdx)+1)
			}

			prevConn = append(prevConn, existedConn)
			conn.prevConn = prevConn

			c.connMap.Store(TgidFd, conn)
			atomic.AddInt64(&c.connectionAdded, 1)
			return nil
		} else {
			return nil
		}
	} else {
		c.connMap.Store(TgidFd, conn)
		atomic.AddInt64(&c.connectionAdded, 1)
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

func (c *Connection4) extractSockKeys() (bpf.AgentSockKey, bpf.AgentSockKey) {
	var key bpf.AgentSockKey
	key.Dip = common.BytesToInt[uint32](c.RemoteIp)
	key.Sip = common.BytesToInt[uint32](c.LocalIp)
	key.Dport = uint32(c.RemotePort)
	key.Sport = uint32(c.LocalPort)
	key.Family = uint32(common.AF_INET) // TODO @ipv6

	var revKey bpf.AgentSockKey
	revKey.Sip = common.BytesToInt[uint32](c.RemoteIp)
	revKey.Dip = common.BytesToInt[uint32](c.LocalIp)
	revKey.Sport = uint32(c.RemotePort)
	revKey.Dport = uint32(c.LocalPort)
	revKey.Family = uint32(common.AF_INET)
	return key, revKey
}

func (c *Connection4) OnClose(needClearBpfMap bool) {
	OnCloseRecordFunc(c)
	c.Status = Closed
	if needClearBpfMap {
		connInfoMap := bpf.GetMap("ConnInfoMap")
		err := connInfoMap.Delete(c.TgidFd)
		if err != nil {
			log.Debugf("clean conn_info_map failed: %v", err)
		} else {
			log.Debugf("clean conn_info_map deleted")
		}
		key, revKey := c.extractSockKeys()
		sockKeyConnIdMap := bpf.GetMap("SockKeyConnIdMap")
		err = sockKeyConnIdMap.Delete(key)
		if err != nil {
			log.Debugf("clean sock_key_conn_id_map key failed: %v", err)
		} else {
			log.Debugf("clean sockKeyConnIdMap deleted key")
		}
		err = sockKeyConnIdMap.Delete(revKey)
		if err != nil {
			log.Debugf("clean sock_key_conn_id_map revkey failed: %v", err)
		} else {
			log.Debugf("clean sockKeyConnIdMap deleted revkey")
		}
		sockXmitMap := bpf.GetMap("SockXmitMap")
		err = sockXmitMap.Delete(key)
		if err == nil {
			log.Debugf("clean sockXmitMap deleted key")
		} else {
			log.Debugf("clean sockXmitMap failed: %v", err)
		}
		err = sockXmitMap.Delete(revKey)
		if err == nil {
			log.Debugf("clean sockXmitMap deleted revkey")
		} else {
			log.Debugf("clean sockXmitMap failed: %v", err)
		}
	}
	monitor.UnregisterMetricExporter(c.StreamEvents)
}

func (c *Connection4) UpdateConnectionTraceable(traceable bool) {
	key, revKey := c.extractSockKeys()
	sockKeyConnIdMap := bpf.GetMap("SockKeyConnIdMap")
	c.doUpdateConnIdMapProtocolToUnknwon(key, sockKeyConnIdMap, traceable)
	c.doUpdateConnIdMapProtocolToUnknwon(revKey, sockKeyConnIdMap, traceable)

	connInfoMap := bpf.GetMap("ConnInfoMap")
	connInfo := bpf.AgentConnInfoT{}
	err := connInfoMap.Lookup(c.TgidFd, &connInfo)
	if err == nil {
		connInfo.NoTrace = !traceable
		connInfoMap.Update(c.TgidFd, &connInfo, ebpf.UpdateExist)
	} else {
		log.Debugf("try to update %s conn_info_map to no_trace, but no entry in map found!", c.ToString())
	}
}

func (c *Connection4) doUpdateConnIdMapProtocolToUnknwon(key bpf.AgentSockKey, m *ebpf.Map, traceable bool) {
	var connIds bpf.AgentConnIdS_t
	err := m.Lookup(&key, &connIds)
	if err == nil {
		connIds.NoTrace = !traceable
		m.Update(&key, &connIds, ebpf.UpdateExist)
	} else {
		log.Debugf("try to update %s conn_id_map to no_trace, but no entry in map found! key: %v", c.ToString(), key)
	}
}

//	func (c *Connection4) OnCloseWithoutClearBpfMap() {
//		c.OnClose(false)
//	}
func (c *Connection4) OnKernEvent(event *bpf.AgentKernEvt) bool {
	isReq, ok := isReq(c, event)
	if event.Len > 0 {
		c.StreamEvents.AddKernEvent(event)
	} else if ok {
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
func (c *Connection4) OnSyscallEvent(data []byte, event *bpf.SyscallEventData, recordChannel chan RecordWithConn) {
	isReq, _ := isReq(c, &event.SyscallEvent.Ke)
	if isReq {
		c.reqStreamBuffer.Add(event.SyscallEvent.Ke.Seq, data, event.SyscallEvent.Ke.Ts)
	} else {
		c.respStreamBuffer.Add(event.SyscallEvent.Ke.Seq, data, event.SyscallEvent.Ke.Ts)
	}

	c.parseStreamBuffer(c.reqStreamBuffer, protocol.Request, &c.ReqQueue, event.SyscallEvent.Ke.Step)
	c.parseStreamBuffer(c.respStreamBuffer, protocol.Response, &c.RespQueue, event.SyscallEvent.Ke.Step)
	c.StreamEvents.AddSyscallEvent(event)

	parser := c.GetProtocolParser(c.Protocol)
	if parser == nil {
		panic("no protocol parser!")
	}

	records := parser.Match(&c.ReqQueue, &c.RespQueue)
	if len(records) != 0 {
		for _, record := range records {
			recordChannel <- RecordWithConn{record, c}
		}
	}
}

func (c *Connection4) parseStreamBuffer(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType, resultQueue *[]protocol.ParsedMessage, step bpf.AgentStepT) {
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
	originPos := streamBuffer.Position0()
	// var parseState protocol.ParseState
	for !stop && !streamBuffer.IsEmpty() {
		parseResult := parser.ParseStream(streamBuffer, messageType)
		// parseState = parseResult.ParseState
		switch parseResult.ParseState {
		case protocol.Success:
			if c.Role == bpf.AgentEndpointRoleTKRoleUnknown && len(parseResult.ParsedMessages) > 0 {
				parsedMessage := parseResult.ParsedMessages[0]
				if (step == bpf.AgentStepTSYSCALL_IN && parsedMessage.IsReq()) || (step == bpf.AgentStepTSYSCALL_OUT && !parsedMessage.IsReq()) {
					c.Role = bpf.AgentEndpointRoleTKRoleServer
				} else {
					c.Role = bpf.AgentEndpointRoleTKRoleClient
				}
				log.Debugf("Update %s role", c.ToString())
				c.resetParseProgress()
			} else {
				if len(parseResult.ParsedMessages) > 0 && parseResult.ParsedMessages[0].IsReq() != (messageType == protocol.Request) {
					streamBuffer.RemovePrefix(parseResult.ReadBytes)
				} else {
					*resultQueue = append(*resultQueue, parseResult.ParsedMessages...)
					streamBuffer.RemovePrefix(parseResult.ReadBytes)
				}
			}
		case protocol.Invalid:
			pos := parser.FindBoundary(streamBuffer, messageType, 1)
			if pos != -1 {
				streamBuffer.RemovePrefix(pos)
				stop = false
			} else {
				removed := c.checkProgress(streamBuffer)
				if removed {
					log.Debugf("Invalid, %s Removed streambuffer head due to stuck", c.ToString())
					stop = false
				} else {
					stop = true
				}
			}
		case protocol.NeedsMoreData:
			removed := c.checkProgress(streamBuffer)
			if removed {
				log.Debugf("Needs more data, %s Removed streambuffer head due to stuck", c.ToString())
				stop = false
			} else {
				stop = true
			}
		case protocol.Ignore:
			stop = false
			streamBuffer.RemovePrefix(parseResult.ReadBytes)
		default:
			panic("invalid parse state!")
		}
	}
	curProgress := streamBuffer.Position0()
	if streamBuffer.IsEmpty() || curProgress != int(originPos) {
		c.updateProgressTime(streamBuffer)
	}
	// if parseState == protocol.Invalid {
	// 	streamBuffer.Clear()
	// }
}
func (c *Connection4) updateProgressTime(sb *buffer.StreamBuffer) {
	if c.reqStreamBuffer == sb {
		c.lastReqMadeProgressTime = time.Now().UnixMilli()
	} else {
		c.lastRespMadeProgressTime = time.Now().UnixMilli()
	}
}
func (c *Connection4) getLastProgressTime(sb *buffer.StreamBuffer) int64 {
	if c.reqStreamBuffer == sb {
		return c.lastReqMadeProgressTime
	} else {
		return c.lastRespMadeProgressTime
	}
}
func (c *Connection4) checkProgress(sb *buffer.StreamBuffer) bool {
	if c.getLastProgressTime(sb) == 0 {
		c.updateProgressTime(sb)
		return false
	}
	if time.Now().UnixMilli()-c.getLastProgressTime(sb) > 1000 {
		sb.RemoveHead()
		return true
	} else {
		return false
	}
}

func isReq(conn *Connection4, event *bpf.AgentKernEvt) (bool, bool) {
	if conn.Role == bpf.AgentEndpointRoleTKRoleUnknown {
		return false, false
	}
	var isReq bool
	if !conn.IsServerSide() {
		isReq = event.ConnIdS.Direct == bpf.AgentTrafficDirectionTKEgress
	} else {
		isReq = event.ConnIdS.Direct == bpf.AgentTrafficDirectionTKIngress
	}
	return isReq, true
}

func (c *Connection4) IsServerSide() bool {
	if c.Role == bpf.AgentEndpointRoleTKRoleClient {
		return false
	} else {
		return true
	}
}

func (c *Connection4) Side() common.SideEnum {
	if c.Role == bpf.AgentEndpointRoleTKRoleClient {
		return common.ClientSide
	} else {
		return common.ServerSide
	}
}
func (c *Connection4) Identity() string {
	cd := common.ConnDesc{
		LocalPort:  c.LocalPort,
		RemotePort: c.RemotePort,
		LocalAddr:  c.LocalIp,
		RemoteAddr: c.RemoteIp,
	}
	return cd.Identity()
}
func (c *Connection4) ToString() string {
	direct := "=>"
	if c.Role == bpf.AgentEndpointRoleTKRoleServer {
		direct = "<="
	} else if c.Role == bpf.AgentEndpointRoleTKRoleClient {
		direct = "=>"
	} else {
		direct = "<unknown>"
	}
	return fmt.Sprintf("[tgid=%d fd=%d][protocol=%d][%s] *%s:%d %s %s:%d", c.TgidFd>>32, uint32(c.TgidFd), c.Protocol, c.StatusString(), c.LocalIp.String(), c.LocalPort, direct, c.RemoteIp.String(), c.RemotePort)
}

func (c *Connection4) StatusString() string {
	if c.Status == Closed {
		return "closed"
	} else {
		return "connect"
	}
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

func (c *Connection4) resetParseProgress() {
	c.reqStreamBuffer.Clear()
	c.respStreamBuffer.Clear()
	c.ReqQueue = c.ReqQueue[:]
	c.RespQueue = c.RespQueue[:]
}
