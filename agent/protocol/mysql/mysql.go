package mysql

import (
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	. "kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"
)

func init() {
	InitCommandLengthRangs()
	protocol.ParsersMap[bpf.AgentTrafficProtocolTKProtocolMySQL] = func() ProtocolStreamParser {
		return &MysqlParser{
			State: &State{
				PreparedStatements: make(map[int]PreparedStatement),
			},
		}
	}
}

func (m *MysqlParser) FindBoundary(streamBuffer *buffer.StreamBuffer, messageType MessageType, startPos int) int {
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
		packetLength32, _ := common.LEndianBytesToKInt[int32](curBuf, kPayloadLengthLength)
		packetLength := int(packetLength32)
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

func (m *MysqlParser) Match(reqStream *[]ParsedMessage, respStream *[]ParsedMessage) []Record {
	records := make([]Record, 0)
	for len(*reqStream) != 0 {
		reqPacket := (*reqStream)[0].(*MysqlPacket)
		commandByte := reqPacket.msg[0]
		command, _ := parseCommand(commandByte)
		syncRespQueue(reqPacket, respStream)
		respPacketsView := getRespView(reqStream, respStream)
		record, state := m.processPackets(reqPacket, respPacketsView)
		// This list contains the commands that, if parsed correctly,
		// are indicative of a higher confidence that this is indeed a MySQL protocol.
		if !m.State.active && state == Success {
			switch command {
			case kConnect:
				fallthrough
			case kInitDB:
				fallthrough
			case kCreateDB:
				fallthrough
			case kDropDB:
				fallthrough
			case kQuery:
				fallthrough
			case kStmtPrepare:
				fallthrough
			case kStmtExecute:
				m.State.active = true
			default:

			}
		}

		if state == NeedsMoreData {
			isLastSeq := len(*reqStream) == 1
			respLooksHealthy := len(respPacketsView) == len(*respStream)
			if isLastSeq && respLooksHealthy {
				common.ProtocolParserLog.Debugln("Appears to be an incomplete message. Waiting for more data")
				break
			}
			common.ProtocolParserLog.Debugf("Didn't have enough response packets, but doesn't appear to be partial either. "+
				"[cmd=%v, cmd_msg=%s resp_packets=%d]", command, reqPacket.msg[1:], len(respPacketsView))
		} else if state == Success {
			records = append(records, record)

		}

		*reqStream = (*reqStream)[1:]
		*respStream = (*respStream)[len(respPacketsView):]
	}
	if !m.State.active {
		return []Record{}
	}
	return records
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
			common.ProtocolParserLog.Infof("Found packet with unexpected sequence ID [expected=%d actual=%d]",
				expectedSeqId,
				respPacket.seqId)
			break
		}
		count++
	}
	return (*respStream)[0:count]
}

func (p *MysqlParser) processPackets(reqPacket *MysqlPacket, respView []ParsedMessage) (protocol.Record, ParseState) {
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
		parseState = ProcessQuit(reqPacket, respView, &record)
		return record, parseState
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
	case kStmtPrepare:
		parseState = p.ProcessStmtPrepare(reqPacket, respView, &record)
		return record, parseState
	case kStmtSendLongData:
		parseState = p.ProcessStmtSendLongData(reqPacket, respView, &record)
		return record, parseState
	case kStmtExecute:
		parseState = p.ProcessStmtExecute(reqPacket, respView, &record)
		return record, parseState
	case kStmtClose:
		parseState := p.ProcessStmtClose(reqPacket, respView, &record)
		return record, parseState
	case kStmtReset:
		parseState := p.ProcessStmtReset(reqPacket, respView, &record)
		return record, parseState
	case kStmtFetch:
		parseState := p.ProcessStmtFetch(reqPacket, respView, &record)
		return record, parseState
	case kProcessInfo:
		fallthrough
	case kChangeUser:
		fallthrough
	case kBinlogDump:
		fallthrough
	case kBinlogDumpGTID:
		fallthrough
	case kTableDump:
		fallthrough
	case kStatistics:
		common.ProtocolParserLog.Warnf("Unimplemented command %d.\n", command)
		parseState = Ignore
		return record, parseState
	default:
		common.ProtocolParserLog.Warnf("Unknown command %d.\n", command)
		parseState = Ignore
		return record, parseState
	}
}
func (m *MysqlParser) ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult {
	head := streamBuffer.Head()
	buf := head.Buffer()
	if len(buf) < kPacketHeaderLength {
		return ParseResult{
			ParseState: NeedsMoreData,
		}
	}

	packet := MysqlPacket{}
	packet.seqId = buf[3]
	packetLength32, _ := common.LEndianBytesToKInt[int32](buf, kPayloadLengthLength)
	packetLength := int(packetLength32)
	if messageType == Request {
		packet.isReq = true
		if len(buf) < kPacketHeaderLength+1 {
			return ParseResult{ParseState: NeedsMoreData}
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

	packet.msg = string(buf[kPacketHeaderLength : kPacketHeaderLength+packetLength])
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
