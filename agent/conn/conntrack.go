package conn

import (
	"encoding/binary"
	"fmt"
	"kyanos/agent/buffer"
	ac "kyanos/agent/common"
	"kyanos/agent/protocol"
	_ "kyanos/agent/protocol/mysql"
	"kyanos/bpf"
	"kyanos/common"
	"kyanos/monitor"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/jefurry/logrus"
)

// var RecordFunc func(protocol.Record, *Connection4) error
var RecordFunc func(protocol.Record, *Connection4) error
var OnCloseRecordFunc func(*Connection4) error

var ConnectionMap *sync.Map = new(sync.Map)

type Connection4 struct {
	LocalIp    net.IP
	RemoteIp   net.IP
	LocalPort  common.Port
	RemotePort common.Port
	Protocol   bpf.AgentTrafficProtocolT
	Role       bpf.AgentEndpointRoleT
	TgidFd     uint64

	ssl bool

	tracable      bpf.AgentConnTraceStateT
	onRoleChanged func()

	TempKernEvents    []*bpf.AgentKernEvt
	TempConnEvents    []*bpf.AgentConnEvtT
	TempSyscallEvents []*bpf.SyscallEventData
	TempSslEvents     []*bpf.SslData
	Status            ConnStatus
	TCPHandshakeStatus

	reqStreamBuffer          *buffer.StreamBuffer
	respStreamBuffer         *buffer.StreamBuffer
	ReqQueue                 map[protocol.StreamId]*protocol.ParsedMessageQueue
	RespQueue                map[protocol.StreamId]*protocol.ParsedMessageQueue
	lastReqMadeProgressTime  int64
	lastRespMadeProgressTime int64
	StreamEvents             *KernEventStream
	protocolParsers          map[bpf.AgentTrafficProtocolT]protocol.ProtocolStreamParser

	MessageFilter protocol.ProtocolFilter
	LatencyFilter protocol.LatencyFilter
	SizeFilter    protocol.SizeFilter

	prevConn []*Connection4
}

func NewConnFromEvent(event *bpf.AgentConnEvtT, p *Processor) *Connection4 {
	TgidFd := uint64(event.ConnInfo.ConnId.Upid.Pid)<<32 | uint64(event.ConnInfo.ConnId.Fd)
	isIpv6 := event.ConnInfo.Laddr.In6.Sin6Family == common.AF_INET6
	conn := &Connection4{
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
		tracable:   bpf.AgentConnTraceStateTUnset,

		MessageFilter: p.messageFilter,
		LatencyFilter: p.latencyFilter,
		SizeFilter:    p.SizeFilter,

		reqStreamBuffer:  buffer.New(1024 * 1024),
		respStreamBuffer: buffer.New(1024 * 1024),
		ReqQueue:         make(map[protocol.StreamId]*protocol.ParsedMessageQueue),
		RespQueue:        make(map[protocol.StreamId]*protocol.ParsedMessageQueue),

		prevConn: []*Connection4{},

		protocolParsers: make(map[bpf.AgentTrafficProtocolT]protocol.ProtocolStreamParser),
	}
	conn.onRoleChanged = func() {
		onRoleChanged(p, conn)
	}
	conn.StreamEvents = NewKernEventStream(conn, 300)
	conn.ConnectStartTs = event.Ts + common.LaunchEpochTime
	sockKey, _ := conn.extractSockKeys()
	ConnectionMap.Store(sockKey, conn)
	return conn
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
				c, loaded := connManager.connMap.LoadAndDelete(tgidFd)
				if loaded {
					conn := c.(*Connection4)
					RemoveConnFromSockKeyMap(conn)
				}
			}
			atomic.AddInt64(&connManager.connectionClosed, int64(len(_needsDelete)))
		}
	}()
	return connManager
}

func RemoveConnFromSockKeyMap(c *Connection4) {
	key, _ := c.extractSockKeys()
	ConnectionMap.Delete(key)
	for _, prev := range c.prevConn {
		key, _ := prev.extractSockKeys()
		ConnectionMap.Delete(key)
	}
}

func (c *ConnManager) AddConnection4(TgidFd uint64, conn *Connection4) error {
	existedConn := c.FindConnection4Exactly(TgidFd)
	if existedConn != nil {
		if !existedConn.IsIpPortEqualsWith(conn) {
			if common.ConntrackLog.Level >= logrus.DebugLevel {
				common.ConntrackLog.Debugf("[AddConnection4] %s find existed conn with same tgidfd but ip port not same: %s", conn.ToString(), existedConn.ToString())
			}
			prevConn := existedConn.prevConn
			existedConn.prevConn = nil
			deleteEndIdx := -1
			for idx := len(prevConn) - 1; idx >= 0; idx-- {
				if prevConn[idx].Status == Closed {
					deleteEndIdx = idx
					break
				}
			}
			if deleteEndIdx != -1 {
				deleted := prevConn[:deleteEndIdx+1]
				for _, conn := range deleted {
					RemoveConnFromSockKeyMap(conn)
				}
				prevConn = prevConn[deleteEndIdx+1:]
				atomic.AddInt64(&c.connectionClosed, int64(deleteEndIdx)+1)
			}

			prevConn = append(prevConn, existedConn)
			conn.prevConn = prevConn

			// transfer existedConn's Events to conn
			conn.TempSyscallEvents = append(conn.TempSyscallEvents, existedConn.TempSyscallEvents...)
			existedConn.TempSyscallEvents = []*bpf.SyscallEventData{}
			conn.TempKernEvents = append(conn.TempKernEvents, existedConn.TempKernEvents...)
			existedConn.TempKernEvents = []*bpf.AgentKernEvt{}
			conn.TempSslEvents = append(conn.TempSslEvents, existedConn.TempSslEvents...)
			existedConn.TempSslEvents = []*bpf.SslData{}

			c.connMap.Store(TgidFd, conn)
			atomic.AddInt64(&c.connectionAdded, 1)
			return nil
		} else {
			if common.ConntrackLog.Level >= logrus.DebugLevel {
				common.ConntrackLog.Debugf("[AddConnection4] %s find existed conn with same tgidfd and same ip port", conn.ToString())
			}

			return nil
		}
	} else {
		if common.ConntrackLog.Level >= logrus.DebugLevel {
			common.ConntrackLog.Debugf("[AddConnection4] %s store into map because no existed conn", conn.ToString())
		}
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

func (c *ConnManager) LookupConnection4ByTimestamp(TgidFd uint64, ts uint64) *Connection4 {
	v, _ := c.connMap.Load(TgidFd)
	connection, _ := v.(*Connection4)
	if connection == nil {
		return nil
	} else {
		if connection.ConnectStartTs < ts {
			return connection
		} else {
			curConnList := connection.prevConn
			for idx := len(curConnList) - 1; idx >= 0; idx-- {
				if curConnList[idx].timeBoundCheck(ts) {
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
	if c.TempSyscallEvents == nil {
		c.TempSyscallEvents = make([]*bpf.SyscallEventData, 0)
	}
	c.TempSyscallEvents = append(c.TempSyscallEvents, e)
}

func (c *Connection4) AddSslEvent(e *bpf.SslData) {
	if c.TempSslEvents == nil {
		c.TempSslEvents = make([]*bpf.SslData, 0)
	}
	c.TempSslEvents = append(c.TempSslEvents, e)
}

func (c *Connection4) ProtocolInferred() bool {
	return (c.Protocol != bpf.AgentTrafficProtocolTKProtocolUnknown) && (c.Protocol != bpf.AgentTrafficProtocolTKProtocolUnset)
}

func (c *Connection4) timeBoundCheck(toCheck uint64) bool {
	if c.ConnectStartTs == 0 {
		return true
	}
	if toCheck < c.ConnectStartTs {
		return false
	}
	if c.CloseTs != 0 && toCheck > c.CloseTs {
		return false
	}
	return true
}

func (c *Connection4) extractSockKeys() (bpf.AgentSockKey, bpf.AgentSockKey) {
	var key bpf.AgentSockKey
	key.Dip = [2]uint64(common.BytesToSockKey(c.RemoteIp))
	key.Sip = [2]uint64(common.BytesToSockKey(c.LocalIp))
	key.Dport = uint16(c.RemotePort)
	key.Sport = uint16(c.LocalPort)
	// key.Family = uint32(common.AF_INET) // TODO @ipv6

	var revKey bpf.AgentSockKey
	revKey.Sip = [2]uint64(common.BytesToSockKey(c.RemoteIp))
	revKey.Dip = [2]uint64(common.BytesToSockKey(c.LocalIp))
	revKey.Sport = uint16(c.RemotePort)
	revKey.Dport = uint16(c.LocalPort)
	return key, revKey
}

func (c *Connection4) OnClose(needClearBpfMap bool) {
	OnCloseRecordFunc(c)
	c.Status = Closed
	if needClearBpfMap {
		var err error
		// connInfoMap := bpf.GetMapFromObjs(bpf.Objs, "ConnInfoMap")
		// err = connInfoMap.Delete(c.TgidFd)
		key, revKey := c.extractSockKeys()
		sockKeyConnIdMap := bpf.GetMapFromObjs(bpf.Objs, "SockKeyConnIdMap")
		err = sockKeyConnIdMap.Delete(key)
		err = sockKeyConnIdMap.Delete(revKey)
		sockXmitMap := bpf.GetMapFromObjs(bpf.Objs, "SockXmitMap")
		err = sockXmitMap.Delete(key)
		err = sockXmitMap.Delete(revKey)
		if err == nil {
		}
	}
	monitor.UnregisterMetricExporter(c.StreamEvents)
}

func (c *Connection4) UpdateConnectionTraceable(traceableState bpf.AgentConnTraceStateT) {
	if c.tracable == traceableState {
		return
	}
	c.tracable = traceableState
	key, _ := c.extractSockKeys()
	sockKeyConnIdMap := bpf.GetMapFromObjs(bpf.Objs, "SockKeyConnIdMap")
	c.doUpdateConnIdMapProtocolToUnknwon(key, sockKeyConnIdMap, traceableState)
	// c.doUpdateConnIdMapProtocolToUnknwon(revKey, sockKeyConnIdMap, traceable)

	connInfoMap := bpf.GetMapFromObjs(bpf.Objs, "ConnInfoMap")
	connInfo := bpf.AgentConnInfoT{}
	err := connInfoMap.Lookup(c.TgidFd, &connInfo)
	if err == nil {
		connInfo.NoTrace = traceableState
		connInfoMap.Update(c.TgidFd, &connInfo, ebpf.UpdateExist)
		if common.ConntrackLog.Level >= logrus.DebugLevel {
			common.ConntrackLog.Debugf("try to update %s conn_info_map to traceable: %v success!", c.ToString(), traceableState)
		}
	} else {
		if common.ConntrackLog.Level >= logrus.DebugLevel {
			common.ConntrackLog.Debugf("try to update %s conn_info_map to traceable: %v, but no entry in map found!", c.ToString(), traceableState)
		}
	}
}

func (c *Connection4) doUpdateConnIdMapProtocolToUnknwon(key bpf.AgentSockKey, m *ebpf.Map, traceable bpf.AgentConnTraceStateT) {
	var connIds bpf.AgentConnIdS_t
	err := m.Lookup(&key, &connIds)
	if err == nil {
		connIds.NoTrace = traceable
		m.Update(&key, &connIds, ebpf.UpdateExist)
		if common.ConntrackLog.Level >= logrus.DebugLevel {
			common.ConntrackLog.Debugf("try to update %s conn_id_map to traceable: %v, success, sock key: %v", c.ToString(), traceable, key)
		}
	} else {
		if common.ConntrackLog.Level >= logrus.DebugLevel {
			common.ConntrackLog.Debugf("try to update %s conn_id_map to traceable: %v, but no entry in map found! key: %v", c.ToString(), traceable, key)
		}
	}
}

func (c *Connection4) IsTraceble() bool {
	return c.tracable <= bpf.AgentConnTraceStateTTraceable
}

//	func (c *Connection4) OnCloseWithoutClearBpfMap() {
//		c.OnClose(false)
//	}
func (c *Connection4) OnKernEvent(event *bpf.AgentKernEvt) bool {
	isReq, ok := isReq(c, event)
	if event.Len > 0 {
		alreadyExisted := c.StreamEvents.AddKernEvent(event)
		if !alreadyExisted {
			return false
		}
	} else if ok {
		if (event.Flags&uint8(common.TCP_FLAGS_SYN) != 0) && !isReq && event.Step == bpf.AgentStepTIP_IN {
			// 接收到Server给的Syn包
			if c.ServerSynReceived {
				if common.ConntrackLog.Level >= logrus.DebugLevel {
					common.ConntrackLog.Debugf("[kern][handshake]%s already received server sync, but now received again!\n", c.ToString())
				}
			} else {
				c.ServerSynReceived = true
				c.ServerSynReceivedTs = event.Ts
				if common.ConntrackLog.Level >= logrus.DebugLevel {
					common.ConntrackLog.Debugf("[kern][handshake]%s received server sync\n", c.ToString())
				}
			}
		}
		if (event.Flags&uint8(common.TCP_FLAGS_ACK) != 0) && isReq && c.ServerSynReceived && !c.ClientAckSent && event.Step == bpf.AgentStepTIP_OUT {
			c.ClientAckSent = true
			c.ClientAckSentTs = event.Ts
			if common.ConntrackLog.Level >= logrus.DebugLevel {
				common.ConntrackLog.Debugf("[kern][handshake]%s sent ack, complete handshake, use time: %d(%d-%d)\n", c.ToString(), c.ClientAckSentTs-c.ConnectStartTs, c.ClientAckSentTs, c.ConnectStartTs)
			}
		}
	}
	return true
}

func getEventTimestamp(ke *bpf.AgentKernEvt, c *Connection4, isReq bool) uint64 {
	side := c.Side()
	if side == common.AllSide {
		return ke.Ts + uint64(ke.TsDelta)
	} else if side == common.ClientSide {
		if isReq {
			return ke.Ts
		} else {
			return ke.Ts + uint64(ke.TsDelta)
		}
	} else {
		if isReq {
			return ke.Ts + uint64(ke.TsDelta)
		} else {
			return ke.Ts
		}
	}
}

func extractHeaderEvent(data []byte, ke *bpf.AgentKernEvt, c *Connection4) *bpf.SyscallEventData {
	if !ke.PrependLengthHeader {
		return nil
	}

	header := make([]byte, 4)
	headerEvt := *ke
	headerEvt.Len = 4
	headerEvt.Seq = ke.Seq - 4
	headerEvt.PrependLengthHeader = false

	headerSyscallEvt := bpf.SyscallEventData{
		SyscallEvent: bpf.SyscallEvent{
			Ke:      headerEvt,
			BufSize: 4,
		},
		Buf: header,
	}
	binary.LittleEndian.PutUint32(header, uint32(ke.LengthHeader))
	if common.ConntrackLog.Level >= logrus.DebugLevel {
		common.ConntrackLog.Debugf("extract header event: %v", headerSyscallEvt)
	}
	return &headerSyscallEvt
}

func (c *Connection4) addDataToBufferAndTryParse(data []byte, ke *bpf.AgentKernEvt) bool {
	addedToBuffer := false
	isReq, _ := isReq(c, ke)
	headerEvt := extractHeaderEvent(data, ke, c)
	if isReq {
		if headerEvt != nil {
			c.reqStreamBuffer.Add(uint64(headerEvt.SyscallEvent.Ke.Seq), headerEvt.Buf, getEventTimestamp(ke, c, isReq))
		}
		addedToBuffer = c.reqStreamBuffer.Add(uint64(ke.Seq), data, getEventTimestamp(ke, c, isReq))
	} else {
		if headerEvt != nil {
			c.respStreamBuffer.Add(uint64(headerEvt.SyscallEvent.Ke.Seq), headerEvt.Buf, getEventTimestamp(ke, c, isReq))
		}
		addedToBuffer = c.respStreamBuffer.Add(uint64(ke.Seq), data, getEventTimestamp(ke, c, isReq))
	}
	if !addedToBuffer {
		return false
	}
	reqSteamMessageType := protocol.Request
	if c.Role == bpf.AgentEndpointRoleTKRoleUnknown {
		reqSteamMessageType = protocol.Unknown
	}
	respSteamMessageType := protocol.Response
	if c.Role == bpf.AgentEndpointRoleTKRoleUnknown {
		respSteamMessageType = protocol.Unknown
	}
	c.parseStreamBuffer(c.reqStreamBuffer, reqSteamMessageType, c.ReqQueue, ke)
	c.parseStreamBuffer(c.respStreamBuffer, respSteamMessageType, c.RespQueue, ke)
	return true
}
func (c *Connection4) OnSslDataEvent(data []byte, event *bpf.SslData, recordChannel chan RecordWithConn) {
	if len(data) > 0 {
		c.addDataToBufferAndTryParse(data, &event.SslEventHeader.Ke)
	}
	c.ssl = true

	c.StreamEvents.AddSslEvent(event)

	parser := c.GetProtocolParser(c.Protocol)
	if parser == nil {
		return
	}

	records := parser.Match(c.ReqQueue, c.RespQueue)
	if len(records) != 0 {
		for _, record := range records {
			recordChannel <- RecordWithConn{record, c}
		}
	}
}

func isSyscallFunctionMultiMessage(f bpf.AgentSourceFunctionT) bool {
	return f == bpf.AgentSourceFunctionTKSyscallSendMMsg ||
		f == bpf.AgentSourceFunctionTKSyscallRecvMMsg ||
		f == bpf.AgentSourceFunctionTKSyscallWriteV ||
		f == bpf.AgentSourceFunctionTKSyscallReadV
}
func fillSyscallDataIfNeeded(data []byte, event *bpf.SyscallEventData, c *Connection4) []byte {

	if event.SyscallEvent.Ke.Len > event.SyscallEvent.BufSize {
		common.ConntrackLog.Debugf("syscall read/write data too len and some data can't be captured, so we need to fill a fake data, len: %d, bufsize: %d", event.SyscallEvent.Ke.Len, event.SyscallEvent.BufSize)

		fakeData, ok := protocol.MakeNewFakeData(event.SyscallEvent.Ke.Len - event.SyscallEvent.BufSize)
		if !ok {
			fakeData = make([]byte, event.SyscallEvent.Ke.Len-event.SyscallEvent.BufSize)
		}
		data = append(data, fakeData...)
		return data
	} else {
		return data
	}
}

func (c *Connection4) OnSyscallEvent(data []byte, event *bpf.SyscallEventData, recordChannel chan RecordWithConn) bool {
	addedToBuffer := true
	if len(data) > 0 {
		if c.ssl {
			if common.ConntrackLog.Level >= logrus.WarnLevel {
				common.ConntrackLog.Warnf("%s is ssl, but receive syscall event with data!", c.ToString())
			}
		} else {
			data = fillSyscallDataIfNeeded(data, event, c)
			addedToBuffer = c.addDataToBufferAndTryParse(data, &event.SyscallEvent.Ke)
		}
	} else if event.SyscallEvent.GetSourceFunction() == bpf.AgentSourceFunctionTKSyscallSendfile {
		// sendfile has no data, so we need to fill a fake data
		common.ConntrackLog.Debug("sendfile has no data, so we need to fill a fake data")
		fakeData, ok := protocol.MakeNewFakeData(event.SyscallEvent.Ke.Len)
		if !ok {
			fakeData = make([]byte, event.SyscallEvent.Ke.Len)
		}
		addedToBuffer = c.addDataToBufferAndTryParse(fakeData, &event.SyscallEvent.Ke)
	} else if isSyscallFunctionMultiMessage(event.SyscallEvent.GetSourceFunction()) && !c.ssl {
		common.ConntrackLog.Debug("syscall read/write multiple message and some data can't be captured, so we need to fill a fake data")
		fakeData, ok := protocol.MakeNewFakeData(event.SyscallEvent.Ke.Len)
		if ok {
			addedToBuffer = c.addDataToBufferAndTryParse(fakeData, &event.SyscallEvent.Ke)
		}
	}
	if !addedToBuffer {
		return false
	}
	c.StreamEvents.AddSyscallEvent(event)

	parser := c.GetProtocolParser(c.Protocol)
	if parser == nil {
		return true
	}

	records := parser.Match(c.ReqQueue, c.RespQueue)
	if len(records) != 0 {
		for _, record := range records {
			recordChannel <- RecordWithConn{record, c}
		}
	}
	return true
}

func (c *Connection4) parseStreamBuffer(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType, resultQueue map[protocol.StreamId]*protocol.ParsedMessageQueue, ke *bpf.AgentKernEvt) {
	parser := c.GetProtocolParser(c.Protocol)
	if parser == nil {
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
	if startPos > 0 {
		if common.ConntrackLog.Level >= logrus.DebugLevel {
			common.ConntrackLog.Debugf("[parseStreamBuffer] %s Removed streambuffer some head data(%d bytes) due to find boundary from %s queue", c.ToString(), startPos, messageType.String())
		}
		streamBuffer.RemovePrefix(startPos)
	}
	originPos := streamBuffer.Position0()
	// var parseState protocol.ParseState
	for !stop && !streamBuffer.IsEmpty() {
		parseResult := parser.ParseStream(streamBuffer, messageType)
		// parseState = parseResult.ParseState
		switch parseResult.ParseState {
		case protocol.Success:
			// common.ConntrackLog.Debugf("[parseStreamBuffer] Success, %s(%s) read bytes: %d, headsize: %d", c.ToString(), messageType.String(), parseResult.ReadBytes, streamBuffer.Head().Len())
			if c.Role == bpf.AgentEndpointRoleTKRoleUnknown && len(parseResult.ParsedMessages) > 0 {
				parsedMessage := parseResult.ParsedMessages[0]
				if (bpf.IsIngressStep(ke.Step) && parsedMessage.IsReq()) || (bpf.IsEgressStep(ke.Step) && !parsedMessage.IsReq()) {
					c.Role = bpf.AgentEndpointRoleTKRoleServer
				} else {
					c.Role = bpf.AgentEndpointRoleTKRoleClient
				}
				if c.onRoleChanged != nil {
					c.onRoleChanged()
				}
				if common.ConntrackLog.Level >= logrus.DebugLevel {
					common.ConntrackLog.Debugf("[parseStreamBuffer] Update %s role", c.ToString())
				}
				c.resetParseProgress()
			} else {
				if len(parseResult.ParsedMessages) > 0 && parseResult.ParsedMessages[0].IsReq() != (messageType == protocol.Request) {
					streamBuffer.RemovePrefix(parseResult.ReadBytes)
				} else {
					for _, parsedMessage := range parseResult.ParsedMessages {
						streamId := parsedMessage.StreamId()
						if resultQueue[streamId] == nil {
							queue := protocol.ParsedMessageQueue(make([]protocol.ParsedMessage, 0))
							resultQueue[streamId] = &queue
						}
						*resultQueue[streamId] = append(*resultQueue[streamId], parsedMessage)
					}
					streamBuffer.RemovePrefix(parseResult.ReadBytes)
				}
			}
		case protocol.Invalid:
			pos := parser.FindBoundary(streamBuffer, messageType, 1)
			if pos != -1 {
				streamBuffer.RemovePrefix(pos)
				if common.ConntrackLog.Level >= logrus.DebugLevel {
					common.ConntrackLog.Debugf("[parseStreamBuffer] Invalid, %s Removed streambuffer some head data(%d bytes) due to stuck from %s queue(found boundary) and continue", c.ToString(), pos, messageType.String())
				}
				stop = false
			} else if c.progressIsStucked(streamBuffer) {
				if streamBuffer.Head().Len() > int(ke.Len) {
					if common.ConntrackLog.Level >= logrus.DebugLevel {
						common.ConntrackLog.Debugf("[parseStreamBuffer] Invalid, %s Removed streambuffer some head data(%d bytes) due to stuck from %s queue", c.ToString(), streamBuffer.Head().Len()-int(ke.Len), messageType.String())
					}
					streamBuffer.RemovePrefix(streamBuffer.Head().Len() - int(ke.Len))
					stop = false
				} else {
					removed := c.checkProgress(streamBuffer)
					if removed {
						if common.ConntrackLog.Level >= logrus.DebugLevel {
							common.ConntrackLog.Debugf("[parseStreamBuffer] Invalid, %s Removed streambuffer head due to stuck from %s queue and continue", c.ToString(), messageType.String())
						}
						stop = false
					} else {
						if common.ConntrackLog.Level >= logrus.DebugLevel {
							common.ConntrackLog.Debugf("[parseStreamBuffer] Invalid, %s Removed streambuffer head due to stuck from %s queue and stop", c.ToString(), messageType.String())
						}
						stop = true
					}
				}
			} else {
				stop = true

				if common.ConntrackLog.Level >= logrus.DebugLevel {
					common.ConntrackLog.Debugf("[parseStreamBuffer] Invalid, %s stop process %s queue", c.ToString(), messageType.String())
				}
			}
		case protocol.NeedsMoreData:
			removed := c.checkProgress(streamBuffer)
			if removed {
				if common.ConntrackLog.Level >= logrus.DebugLevel {
					common.ConntrackLog.Debugf("[parseStreamBuffer] Needs more data, %s Removed streambuffer head due to stuck from %s queue", c.ToString(), messageType.String())
				}
				stop = false
			} else {
				// common.ConntrackLog.Debugf("[parseStreamBuffer] Needs more data, %s stop processing %s queue, headsize: %d", c.ToString(), messageType.String(), streamBuffer.Head().Len())
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
	if streamBuffer.IsEmpty() || curProgress != originPos {
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
	// common.ConntrackLog.Debugf("%s update progress time to %v", c.ToString(), time.Now())
}
func (c *Connection4) getLastProgressTime(sb *buffer.StreamBuffer) int64 {
	if c.reqStreamBuffer == sb {
		return c.lastReqMadeProgressTime
	} else {
		return c.lastRespMadeProgressTime
	}
}

func (c *Connection4) progressIsStucked(sb *buffer.StreamBuffer) bool {
	if c.getLastProgressTime(sb) == 0 {
		c.updateProgressTime(sb)
		return false
	}
	headTime, ok := sb.FindTimestampBySeq(uint64(sb.Position0()))
	stuckDuration := time.Now().UnixMilli() - int64(common.NanoToMills(headTime))
	if !ok || stuckDuration > int64(ac.Options.MaxAllowStuckTimeMills) {
		return true
	}
	if common.ConntrackLog.Level >= logrus.DebugLevel {
		common.ConntrackLog.Debugf("%s stucked for %d ms, less than %d", c.ToString(), stuckDuration, ac.Options.MaxAllowStuckTimeMills)
	}
	return false
}
func (c *Connection4) checkProgress(sb *buffer.StreamBuffer) bool {
	if c.getLastProgressTime(sb) == 0 {
		c.updateProgressTime(sb)
		return false
	}
	headTime, ok := sb.FindTimestampBySeq(uint64(sb.Position0()))
	now := time.Now().UnixMilli()
	headTimeMills := int64(common.NanoToMills(headTime))
	if !ok || now-headTimeMills > int64(ac.Options.MaxAllowStuckTimeMills) {
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
		isReq = event.Step <= bpf.AgentStepTNIC_OUT
	} else {
		isReq = event.Step >= bpf.AgentStepTNIC_IN
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

func (c *Connection4) IsSsl() bool {
	return c.ssl
}
func endpointRoleAsSideEnum(role bpf.AgentEndpointRoleT) common.SideEnum {
	if role == bpf.AgentEndpointRoleTKRoleClient {
		return common.ClientSide
	} else if role == bpf.AgentEndpointRoleTKRoleServer {
		return common.ServerSide
	} else {
		return common.AllSide
	}
}
func (c *Connection4) Side() common.SideEnum {
	return endpointRoleAsSideEnum(c.Role)
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
	var sslString string
	if c.ssl {
		sslString = "[ssl]"
	}
	return fmt.Sprintf("[tgid=%d fd=%d][protocol=%d][%s]%s *%s:%d %s %s:%d", c.TgidFd>>32, uint32(c.TgidFd), c.Protocol, c.StatusString(), sslString, c.LocalIp.String(), c.LocalPort, direct, c.RemoteIp.String(), c.RemotePort)
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
	c.ReqQueue = make(map[protocol.StreamId]*protocol.ParsedMessageQueue)
	c.RespQueue = make(map[protocol.StreamId]*protocol.ParsedMessageQueue)
}
