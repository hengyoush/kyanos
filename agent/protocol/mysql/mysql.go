package mysql

import (
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	. "kyanos/agent/protocol"
	"kyanos/common"
)

var _ protocol.ProtocolStreamParser = MysqlParser{}

// See https://dev.mysql.com/doc/internals/en/mysql-packet.html.
const kPacketHeaderLength int = 4

// Part of kPacketHeaderLength.
const kPayloadLengthLength int = 3

type MysqlParser struct {
}

var _ ParsedMessage = &MysqlPacket{}

type MysqlPacket struct {
	FrameBase
	seqId byte
	msg   string
	cmd   int
	isReq bool
}

func (m *MysqlPacket) FormatToString() string {
	return fmt.Sprintf("base=[%s] seqId=[%d] msg=[%s] isReq=[%v]", m.FrameBase.String(), m.seqId, m.msg, m.isReq)
}

func (m *MysqlPacket) IsReq() bool {
	return m.isReq
}

type MysqlRequestPacket struct {
	MysqlPacket
	cmd byte
}

func init() {
	InitCommandLengthRangs()
}

func (m MysqlParser) FindBoundary(streamBuffer *buffer.StreamBuffer, messageType MessageType, startPos int) int {
	head := streamBuffer.Head()
	buf := head.Buffer()
	if len(buf) < kPacketHeaderLength {
		return -1
	}
	if messageType == Response {
		return -1
	}

	for idx := startPos; idx < len(buf)-kPacketHeaderLength; idx++ {
		curBuf := buf[idx:]
		packetLength := common.LEndianBytesToInt(curBuf, kPayloadLengthLength)
		sequenceId := buf[kPayloadLengthLength]
		commandByte := curBuf[kPacketHeaderLength]
		command, ok := parseCommand(commandByte)

		// Requests must have sequence id of 0.
		if sequenceId != 0 {
			continue
		}

		// If the command byte doesn't decode to a valid command, then this can't a message boundary.
		if !ok {
			continue
		}

		lengthRange := commandLengthRanges[command]
		if packetLength < lengthRange[0] || packetLength > lengthRange[1] {
			continue
		}

		return idx
	}
	return -1
}

func (m MysqlParser) Match(reqStream *[]ParsedMessage, respStream *[]ParsedMessage) []Record {
	// for len(*reqStream) != 0 {
	// reqPacket := (*reqStream)[0].(*MysqlPacket)
	// commandByte := reqPacket.msg[0]
	// command, _ := parseCommand(commandByte)
	// syncRespQueue(reqPacket, respStream)
	// respPacketsView := getRespView(reqStream, respStream)

	// }
	panic("unimplemented")
}

func syncRespQueue(reqPacket *MysqlPacket, respStream *[]ParsedMessage) {
	for len(*respStream) != 0 && (*respStream)[0].TimestampNs() < reqPacket.TimestampNs() {
		*respStream = (*respStream)[1:]
	}
}

func getRespView(reqStream *[]ParsedMessage, respStream *[]ParsedMessage) []ParsedMessage {
	count := 0
	for _, resp := range *respStream {
		if len(*reqStream) > 1 && resp.TimestampNs() > (*reqStream)[1].TimestampNs() {
			break
		}
		respPacket := resp.(*MysqlPacket)
		expectedSeqId := count + 1
		if respPacket.seqId != byte(expectedSeqId) {
			common.Log.Infof("Found packet with unexpected sequence ID [expected=%d actual=%d]",
				expectedSeqId,
				respPacket.seqId)
			break
		}
		count++
	}
	return (*respStream)[0:count]
}

func processPackets(reqPacket *MysqlPacket, respView []ParsedMessage) (protocol.Record, ParseState) {
	command, _ := parseCommand(reqPacket.msg[0])
	var parseState ParseState
	record := Record{}
	switch command {
	// Internal commands with response: ERR_Packet.
	case kConnect:
		fallthrough
	case kConnectOut:
		fallthrough
	case kTime:
		fallthrough
	case kDelayedInsert:
		fallthrough
	case kDaemon:
		parseState = processRequestWithBasicResponse(reqPacket, false, respView, &record)
		return record, parseState
	case kInitDB:
		fallthrough
	case kCreateDB:
		fallthrough
	case kDropDB:
		parseState = processRequestWithBasicResponse(reqPacket, true, respView, &record)
		return record, parseState
		// Basic Commands with response: OK_Packet or ERR_Packet
	case kSleep:
		fallthrough
	case kRegisterSlave:
		fallthrough
	case kResetConnection:
		fallthrough
	case kProcessKill:
		fallthrough
	case kRefresh:
		fallthrough
	case kPing:
		parseState = processRequestWithBasicResponse(reqPacket, false, respView, &record)
		return record, parseState
	case kQuit: // Response: OK_Packet or a connection close.
		panic("todo")
		// Basic Commands with response: EOF_Packet or ERR_Packet.
	case kShutdown:
		fallthrough
	case kSetOption:
		fallthrough
	case kDebug:
		parseState = processRequestWithBasicResponse(reqPacket, false, respView, &record)
		return record, parseState
	case kQuery:
		parseState = processQuery(reqPacket, respView, &record)
		return record, parseState
	default:
		panic("todo")
	}
}

func ProcessStmtPrepare(reqPacket *MysqlPacket, respView []ParsedMessage, record *Record) ParseState {
	var resultReq *MysqlPacket
	resultReq = handleStringRequest(reqPacket)
	record.Req = resultReq

	if len(respView) == 0 {
		return NeedsMoreData
	}
	firstResp := respView[0].(*MysqlPacket)
	if isErrPacket(firstResp) {
		handleErrMessage(respView, record)
		return Success
	}
	panic("todo")
}

func processQuery(reqPacket *MysqlPacket, respView []ParsedMessage, record *Record) ParseState {
	var resultReq *MysqlPacket
	resultReq = handleStringRequest(reqPacket)
	record.Req = resultReq

	if len(respView) == 0 {
		return NeedsMoreData
	}

	firstResp := respView[0].(*MysqlPacket)
	if isErrPacket(firstResp) {
		handleErrMessage(respView, record)
		return Success
	}

	if isOkPacket(firstResp) {
		handleOkMessage(respView, record)
	}
	return Success
}

func processRequestWithBasicResponse(reqPacket *MysqlPacket, stringReq bool,
	respView []ParsedMessage, record *Record) ParseState {
	var resultReq *MysqlPacket
	if stringReq {
		resultReq = handleNonStringRequest(reqPacket)
	} else {
		resultReq = handleNonStringRequest(reqPacket)
	}
	record.Req = resultReq

	if len(respView) == 0 {
		return NeedsMoreData
	}

	if len(respView) > 1 {
		common.Log.Warnf(
			"Did not expect more than one response packet [cmd=%c, num_extra_packets=%d].\n",
			reqPacket.msg[0], len(respView)-1)
		return Invalid
	}

	respPacket := respView[0].(*MysqlPacket)
	record.Resp = respPacket
	if isOkPacket(respPacket) || isEOFPacketAll(respPacket) {
		return Success
	}

	if isErrPacket(respPacket) {
		return handleErrMessage(respView, record)
	}

	return Invalid
}

func handleStringRequest(reqPacket *MysqlPacket) *MysqlPacket {
	if len(reqPacket.msg) == 0 {
		panic("A request cannot have an empty payload.")
	}
	request := *reqPacket
	cmd, _ := parseCommand(reqPacket.msg[0])
	request.cmd = int(cmd)
	request.msg = reqPacket.msg[1:]
	return &request
}

func handleNonStringRequest(reqPacket *MysqlPacket) *MysqlPacket {
	if len(reqPacket.msg) == 0 {
		panic("A request cannot have an empty payload.")
	}
	request := *reqPacket
	cmd, _ := parseCommand(reqPacket.msg[0])
	request.cmd = int(cmd)
	request.msg = reqPacket.msg[:]
	return &request
}

func handleOkMessage(respPackets []ParsedMessage, record *Record) ParseState {
	resp := respPackets[0].(*MysqlPacket)
	const kMinOKPacketSize int = 7
	if len(resp.msg) < kMinOKPacketSize {
		common.Log.Warnln("Insufficient number of bytes for an OK packet.")
		return Invalid
	}
	record.Resp = resp
	if len(respPackets) > 1 {
		common.Log.Warningf("Did not expect additional packets after OK packet [num_extra_packets=%d].",
			len(respPackets)-1)
		return Invalid
	}
	return Success
}

func handleErrMessage(respPackets []ParsedMessage, record *Record) ParseState {
	mysqlResp := respPackets[0].(*MysqlPacket)

	// Format of ERR packet:
	//   1  header: 0xff
	//   2  error_code
	//   1  sql_state_marker
	//   5  sql_state
	//   x  error_message
	// https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
	const kMinErrPacketSize int = 9
	const kErrorCodePos int = 1
	const kErrorCodeSize int = 2
	const kErrorMessagePos int = 9
	if len(mysqlResp.msg) < kMinErrPacketSize {
		common.Log.Warnln("Insufficient number of bytes for an error packet.")
		return Invalid
	}

	record.Resp.(*MysqlPacket).msg = mysqlResp.msg[kErrorMessagePos:]
	common.LEndianBytesToKInt[int32]([]byte(mysqlResp.msg[kErrorCodePos:]), kErrorCodeSize)
	if len(respPackets) > 1 {
		common.Log.Warnf("Did not expect additional packets after error packet [num_extra_packets=%d].",
			len(respPackets)-1)
		return Invalid
	}
	return Success
}

func (m MysqlParser) ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult {
	head := streamBuffer.Head()
	buf := head.Buffer()
	if len(buf) < kPacketHeaderLength {
		return ParseResult{
			ParseState: NeedsMoreData,
		}
	}

	packet := MysqlPacket{}
	packet.seqId = buf[3]
	packetLength := common.LEndianBytesToInt(buf, kPayloadLengthLength)
	if messageType == Request {
		if len(buf) < kPacketHeaderLength+1 {
			return ParseResult{ParseState: Invalid}
		}

		commandByte := buf[kPacketHeaderLength]
		command, ok := parseCommand(commandByte)
		if !ok {
			return ParseResult{ParseState: Invalid}
		}

		lengthRange := commandLengthRanges[command]
		if packetLength < lengthRange[0] || packetLength > lengthRange[1] {
			return ParseResult{ParseState: Invalid}
		}
	}

	bufferLength := len(buf)
	if bufferLength < kPacketHeaderLength+packetLength {
		return ParseResult{ParseState: NeedsMoreData}
	}

	packet.msg = string(buf[kPacketHeaderLength:packetLength])
	fb, ok := CreateFrameBase(streamBuffer, kPacketHeaderLength+packetLength)
	if !ok {
		return ParseResult{
			ParseState: Ignore,
			ReadBytes:  kPacketHeaderLength + packetLength,
		}
	} else {
		packet.FrameBase = fb
		return ParseResult{
			ParseState:     Success,
			ParsedMessages: []ParsedMessage{&packet},
			ReadBytes:      kPacketHeaderLength + packetLength,
		}
	}
}
