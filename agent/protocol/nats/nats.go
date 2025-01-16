package nats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"
	"strconv"
	"strings"
)

const (
	_CRLF_ = "\r\n"
)

type NatsProtocolCreator func() NatsProtocolParser

var natsParsersMap map[string]NatsProtocolCreator = make(map[string]NatsProtocolCreator)

func GetNatsProtocolParser(protocol string) NatsProtocolParser {
	parser, ok := natsParsersMap[protocol]
	if ok {
		return parser()
	}
	return nil
}

func init() {
	protocol.ParsersMap[bpf.AgentTrafficProtocolTKProtocolNATS] = func() protocol.ProtocolStreamParser {
		return &NatsStreamParser{}
	}
	natsParsersMap[INFO.String()] = func() NatsProtocolParser { return &Info{} }
	natsParsersMap[CONNECT.String()] = func() NatsProtocolParser { return &Connect{} }
	natsParsersMap[PUB.String()] = func() NatsProtocolParser { return &Pub{} }
	natsParsersMap[HPUB.String()] = func() NatsProtocolParser { return &Hpub{} }
	natsParsersMap[SUB.String()] = func() NatsProtocolParser { return &Sub{} }
	natsParsersMap[UNSUB.String()] = func() NatsProtocolParser { return &Unsub{} }
	natsParsersMap[MSG.String()] = func() NatsProtocolParser { return &Msg{} }
	natsParsersMap[HMSG.String()] = func() NatsProtocolParser { return &Hmsg{} }
	natsParsersMap[PING.String()] = func() NatsProtocolParser { return &Ping{} }
	natsParsersMap[PONG.String()] = func() NatsProtocolParser { return &Pong{} }
	natsParsersMap[OK.String()] = func() NatsProtocolParser { return &Ok{} }
	natsParsersMap[ERR.String()] = func() NatsProtocolParser { return &Err{} }
}

func (parser *NatsStreamParser) Match(reqStreams map[protocol.StreamId]*protocol.ParsedMessageQueue, respStreams map[protocol.StreamId]*protocol.ParsedMessageQueue) []protocol.Record {
	records := make([]protocol.Record, 0)

	for _, id := range []protocol.StreamId{0, 1} {
		if records_ := match(reqStreams, respStreams, id); len(records_) > 0 {
			records = append(records, records_...)
		}
	}
	return records
}
func match(reqStreams map[protocol.StreamId]*protocol.ParsedMessageQueue, respStreams map[protocol.StreamId]*protocol.ParsedMessageQueue, id protocol.StreamId) []protocol.Record {
	reqStream, ok1 := reqStreams[id]
	respStream, ok2 := respStreams[id]
	if !ok1 || !ok2 {
		return []protocol.Record{}
	}
	return protocol.MatchByTimestamp(reqStream, respStream)
}

func (parser *NatsStreamParser) FindBoundary(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType, startPos int) int {
	return 0
}

func (parser *NatsStreamParser) ParseStream(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType) protocol.ParseResult {
	buffer := streamBuffer.Head().Buffer()
	common.ProtocolParserLog.Debugf("NATSStreamParser received buffer length: %d, %x %v", len(buffer), string(buffer), messageType)

	index := readField(buffer)
	if index < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	method := strings.ToUpper(string(buffer[:index]))
	common.ProtocolParserLog.Debugf("NATSStreamParser method: %v", string(method))

	natsParser := GetNatsProtocolParser(method)
	if natsParser == nil {
		common.ProtocolParserLog.Debugf("NATSStreamParser unsuport method[%v]", method)
		index_ := readLine(buffer)
		if index_ < 0 {
			return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
		} else {
			return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: index_}
		}
	}
	return natsParser.Parse(buffer[index-len(method):], index-len(method), messageType, streamBuffer)
}

func readField(buffer []byte) int {
	return bytes.IndexFunc(buffer, func(b rune) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' })
}

func readLine(buffer []byte) int {
	index := bytes.Index(buffer, []byte(_CRLF_))
	if index >= 0 {
		index += len(_CRLF_)
	}
	return index
}

func splitFields(buffer []byte) [][]byte {
	return bytes.FieldsFunc(buffer, func(r rune) bool { return r == ' ' || r == '\t' })
}

func trimFiled(buffer []byte) []byte {
	return bytes.TrimFunc(buffer, func(r rune) bool { return r == ' ' || r == '\t' })
}

func (msg *NatsMessage) FormatToSummaryString() string {
	return fmt.Sprintf("[protocol=[%v], subject=[%v]", msg.ProtocolCode.String(), msg.Subject)
}

func (msg *NatsMessage) FormatToString() string {
	return fmt.Sprintf("protocol=[%v], subject=[%v], detail=[%s]", msg.ProtocolCode.String(), msg.Subject, msg.Buf)
}

func (msg *NatsMessage) IsReq() bool {
	return msg.isReq
}

func (msg *NatsMessage) StreamId() protocol.StreamId {
	if msg.ProtocolCode == PING || msg.ProtocolCode == PONG {
		return 1
	}
	return 0
}

func (msg *NatsMessage) packFrameBase(streamBuffer *buffer.StreamBuffer, readBytes int) bool {
	if streamBuffer != nil {
		fb, ok := protocol.CreateFrameBase(streamBuffer, readBytes)
		if !ok {
			common.ProtocolParserLog.Debugf("NATS Failed to create FrameBase for frameSize=%d", readBytes)
			return false
		}
		msg.FrameBase = fb
	}
	return true
}

// Info
func (m *Info) String() string {
	return fmt.Sprintf("Protocol:INFO,ServerID:%v,ServerName:%v,Version:%v,GoVersion:%v,Host:%v,Port:%v,MaxPayload:%v,TLSRequired:%v",
		m.ServerID, m.ServerName, m.Version, m.GoVersion, m.Host, m.Port, m.MaxPayload, m.TLSRequired)
}
func (m *Info) Parse(payload []byte, offset int, messageType protocol.MessageType, streamBuffer *buffer.StreamBuffer) protocol.ParseResult {
	// INFO {"option_name":option_value,...}␍␊
	common.ProtocolParserLog.Debugf("NATS Parse Info:%d, %d, %x", offset, len(payload), string(payload))

	packetLen := readLine(payload)
	if packetLen < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) != 2 {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	// if strings.ToUpper(string(parts[0])) != "INFO" {
	// 	return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	// }

	msg := Info{}
	err := json.Unmarshal(parts[1], &msg)
	if err != nil {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}

	packetEnd := packetLen
	msg.ProtocolCode = INFO
	msg.isReq = false
	msg.Buf = payload[:packetEnd]
	common.ProtocolParserLog.Debugf("NATS Parsed Info:[%v], ReadBytes:%d, %v, %v", msg.String(), packetEnd, messageType, msg.isReq)
	if ok := msg.packFrameBase(streamBuffer, packetEnd+offset); !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetEnd + offset}
	}
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&msg},
		ReadBytes:      packetEnd + offset,
	}
}

// Connect
func (m *Connect) String() string {
	return fmt.Sprintf("Protocol:CONNECT,Verbose:%v,Pedantic:%v,TLSRequired:%v,Name:%v,Version:%v",
		m.Verbose, m.Pedantic, m.TLSRequired, m.Name, m.Version)
}
func (m *Connect) Parse(payload []byte, offset int, messageType protocol.MessageType, streamBuffer *buffer.StreamBuffer) protocol.ParseResult {
	// CONNECT {"option_name":option_value,...}␍␊
	common.ProtocolParserLog.Debugf("NATS Parse Connect:%d, %d, %x", offset, len(payload), string(payload))

	packetLen := readLine(payload)
	if packetLen < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) != 2 {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	// if strings.ToUpper(string(parts[0])) != "CONNECT" {
	// 	return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen}
	// }

	msg := Connect{}
	err := json.Unmarshal(parts[1], &msg)
	if err != nil {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}

	packetEnd := packetLen
	msg.ProtocolCode = CONNECT
	msg.isReq = true
	msg.Buf = payload[:packetEnd]
	common.ProtocolParserLog.Debugf("NATS Parsed Connect:[%v], ReadBytes:%d, %v, %v", msg.String(), packetEnd, messageType, msg.isReq)
	if ok := msg.packFrameBase(streamBuffer, packetEnd+offset); !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetEnd + offset}
	}
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&msg},
		ReadBytes:      packetEnd + offset,
	}
}

// Pub
func (m *Pub) String() string {
	return fmt.Sprintf("Protocol:PUB,Subject:%v,ReplyTo:%v,PayloadSize:%d,Payload:%x", m.Subject, m.ReplyTo, m.PayloadSize, m.Payload)
}
func (m *Pub) Parse(payload []byte, offset int, messageType protocol.MessageType, streamBuffer *buffer.StreamBuffer) protocol.ParseResult {
	// PUB <subject> [reply-to] <#bytes>␍␊[payload]␍␊
	common.ProtocolParserLog.Debugf("NATS Parse Pub:%d, %d, %x", offset, len(payload), string(payload))

	packetLen := readLine(payload)
	if packetLen < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) < 3 || len(parts) > 4 {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	// if strings.ToUpper(string(parts[0])) != "PUB" {
	// 	return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen}
	// }

	msg := Pub{}
	msg.Subject = string(parts[1])

	index := 2
	if len(parts) == 4 {
		msg.ReplyTo = string(parts[index])
		index++
	}
	payloadSize, err := strconv.Atoi(string(parts[index]))
	if err != nil {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	packetEnd := packetLen + payloadSize + len(_CRLF_)
	if len(payload) < packetEnd {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	if !bytes.HasPrefix(payload[packetLen+payloadSize:], []byte(_CRLF_)) {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	msg.PayloadSize = payloadSize
	msg.Payload = payload[packetLen : packetLen+payloadSize]

	msg.ProtocolCode = PUB
	msg.isReq = true
	msg.NatsMessage.Subject = msg.Subject
	msg.Buf = payload[:packetEnd]
	common.ProtocolParserLog.Debugf("NATS Parsed Pub:[%v], ReadBytes:%d, %v, %v", msg.String(), packetEnd, messageType, msg.isReq)
	if ok := msg.packFrameBase(streamBuffer, packetEnd+offset); !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetEnd + offset}
	}
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&msg},
		ReadBytes:      packetEnd + offset,
	}
}

// Hpub
func (m *Hpub) String() string {
	return fmt.Sprintf("Protocol:HPUB,Subject:%v,ReplyTo:%v,HeaderSize:%d,PayloadSize:%d,HeaderVersion:%v,Headers:%v,Payload:%x",
		m.Subject, m.ReplyTo, m.HeaderSize, m.PayloadSize, m.HeaderVersion, m.Headers, m.Payload)
}
func (m *Hpub) Parse(payload []byte, offset int, messageType protocol.MessageType, streamBuffer *buffer.StreamBuffer) protocol.ParseResult {
	// HPUB <subject> [reply-to] <#header bytes> <#total bytes>␍␊[headers]␍␊␍␊[payload]␍␊
	common.ProtocolParserLog.Debugf("NATS Parse Hpub:%d, %d, %x", offset, len(payload), string(payload))

	packetLen := readLine(payload)
	if packetLen < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) < 4 || len(parts) > 5 {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	// if strings.ToUpper(string(parts[0])) != "HPUB" {
	// 	return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen}
	// }

	msg := Hpub{}
	msg.Subject = string(parts[1])

	index := 2
	if len(parts) == 5 {
		msg.ReplyTo = string(parts[2])
		index++
	}

	headerSize, err_1 := strconv.Atoi(string(parts[index]))
	totalSize, err_2 := strconv.Atoi(string(parts[index+1]))
	if err_1 != nil || err_2 != nil || headerSize > totalSize {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}

	packetEnd := packetLen + totalSize + len(_CRLF_)
	if len(payload) < packetEnd {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	if !bytes.HasSuffix(payload[:packetLen+headerSize], []byte(_CRLF_)) || !bytes.HasPrefix(payload[packetLen+totalSize:], []byte(_CRLF_)) {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}

	msg.HeaderSize = headerSize
	msg.PayloadSize = totalSize - headerSize

	headerVersionLen := readLine(payload[packetLen:])
	msg.HeaderVersion = string(payload[packetLen : packetLen+headerVersionLen-len(_CRLF_)])

	msg.Headers = make(map[string][]string)
	headerLines := bytes.Split(payload[packetLen+headerVersionLen:packetLen+headerSize], []byte(_CRLF_))
	for _, line := range headerLines {
		if len(line) == 0 {
			continue
		}
		parts := bytes.SplitN(line, []byte(":"), 2)
		if len(parts) != 2 {
			continue
		}
		key := string(bytes.TrimSpace(parts[0]))
		value := string(bytes.TrimSpace(parts[1]))

		if _, ok := msg.Headers[key]; !ok {
			msg.Headers[key] = []string{}
		}
		msg.Headers[key] = append(msg.Headers[key], value)
	}

	msg.Payload = payload[packetLen+headerSize : packetLen+totalSize]

	msg.ProtocolCode = HPUB
	msg.isReq = true
	msg.NatsMessage.Subject = msg.Subject
	msg.Buf = payload[:packetEnd]
	common.ProtocolParserLog.Debugf("NATS Parsed Hpub:[%v], ReadBytes:%d, %v, %v", msg.String(), packetEnd, messageType, msg.isReq)
	if ok := msg.packFrameBase(streamBuffer, packetEnd+offset); !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetEnd + offset}
	}
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&msg},
		ReadBytes:      packetEnd + offset,
	}
}

// Sub
func (m *Sub) String() string {
	return fmt.Sprintf("Protocol:SUB,Subject:%v,QueueGroup:%v,Sid:%v",
		m.Subject, m.QueueGroup, m.Sid)
}
func (m *Sub) Parse(payload []byte, offset int, messageType protocol.MessageType, streamBuffer *buffer.StreamBuffer) protocol.ParseResult {
	// SUB <subject> [queue group] <sid>␍␊
	common.ProtocolParserLog.Debugf("NATS Parse Sub:%d, %d, %x", offset, len(payload), string(payload))

	packetLen := readLine(payload)
	if packetLen < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) < 3 || len(parts) > 4 {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	// if strings.ToUpper(string(parts[0])) != "SUB" {
	// 	return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen}
	// }

	msg := Sub{}
	msg.Subject = string(parts[1])

	index := 2
	if len(parts) == 4 {
		msg.QueueGroup = string(parts[2])
		index++
	}
	msg.Sid = string(parts[index])

	packetEnd := packetLen
	msg.ProtocolCode = SUB
	msg.isReq = true
	msg.NatsMessage.Subject = msg.Subject
	msg.Buf = payload[:packetEnd]
	common.ProtocolParserLog.Debugf("NATS Parsed Sub:[%v], ReadBytes:%d, %v, %v", msg.String(), packetEnd, messageType, msg.isReq)
	if ok := msg.packFrameBase(streamBuffer, packetEnd+offset); !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetEnd + offset}
	}
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&msg},
		ReadBytes:      packetEnd + offset,
	}
}

// Unsub
func (m *Unsub) String() string {
	return fmt.Sprintf("Protocol:UNSUB,Sid:%v,MaxMsgs:%v",
		m.Sid, m.MaxMsgs)
}
func (m *Unsub) Parse(payload []byte, offset int, messageType protocol.MessageType, streamBuffer *buffer.StreamBuffer) protocol.ParseResult {
	// UNSUB <sid> [max_msgs]␍␊
	common.ProtocolParserLog.Debugf("NATS Parse Unsub:%d, %d, %x", offset, len(payload), string(payload))

	packetLen := readLine(payload)
	if packetLen < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) < 2 || len(parts) > 3 {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	// if strings.ToUpper(string(parts[0])) != "UNSUB" {
	// 	return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen}
	// }

	msg := Unsub{}
	msg.Sid = string(parts[1])

	if len(parts) == 3 {
		maxMsgs, err := strconv.Atoi(string(parts[2]))
		if err != nil {
			return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
		}
		msg.MaxMsgs = maxMsgs
	}

	packetEnd := packetLen
	msg.ProtocolCode = UNSUB
	msg.isReq = true
	msg.Buf = payload[:packetEnd]
	common.ProtocolParserLog.Debugf("NATS Parsed Unsub:[%v], ReadBytes:%d, %v, %v", msg.String(), packetEnd, messageType, msg.isReq)
	if ok := msg.packFrameBase(streamBuffer, packetEnd+offset); !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetEnd + offset}
	}
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&msg},
		ReadBytes:      packetEnd + offset,
	}
}

// Msg
func (m *Msg) String() string {
	return fmt.Sprintf("Protocol:MSG,Subject:%v,Sid:%v,ReplyTo:%v,PayloadSize:%d,Payload:%x",
		m.Subject, m.Sid, m.ReplyTo, m.PayloadSize, m.Payload)
}
func (m *Msg) Parse(payload []byte, offset int, messageType protocol.MessageType, streamBuffer *buffer.StreamBuffer) protocol.ParseResult {
	// MSG <subject> <sid> [reply-to] <#bytes>␍␊[payload]␍␊
	common.ProtocolParserLog.Debugf("NATS Parse Msg:%d, %d, %x", offset, len(payload), string(payload))

	packetLen := readLine(payload)
	if packetLen < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) < 4 || len(parts) > 5 {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	// if strings.ToUpper(string(parts[0])) != "MSG" {
	// 	return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen}
	// }

	msg := Msg{}
	msg.Subject = string(parts[1])
	msg.Sid = string(parts[2])

	index := 3
	if len(parts) == 5 {
		msg.ReplyTo = string(parts[3])
		index++
	}

	payloadSize, err := strconv.Atoi(string(parts[index]))
	if err != nil {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	packetEnd := packetLen + payloadSize + len(_CRLF_)
	if len(payload) < packetEnd {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	if !bytes.HasPrefix(payload[packetLen+payloadSize:], []byte(_CRLF_)) {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	msg.PayloadSize = payloadSize
	msg.Payload = payload[packetLen : packetLen+payloadSize]

	msg.ProtocolCode = MSG
	msg.isReq = false
	msg.NatsMessage.Subject = msg.Subject
	msg.Buf = payload[:packetEnd]
	common.ProtocolParserLog.Debugf("NATS Parsed Msg:[%v], ReadBytes:%d, %v, %v", msg.String(), packetEnd, messageType, msg.isReq)
	if ok := msg.packFrameBase(streamBuffer, packetEnd+offset); !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetEnd + offset}
	}
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&msg},
		ReadBytes:      packetEnd + offset,
	}
}

// Hmsg
func (m *Hmsg) String() string {
	return fmt.Sprintf("Protocol:HMSG,Subject:%v,Sid:%v,ReplyTo:%v,HeaderSize:%d,PayloadSize:%d,HeaderVersion:%v,Headers:%v,Payload:%x",
		m.Subject, m.Sid, m.ReplyTo, m.HeaderSize, m.PayloadSize, m.HeaderVersion, m.Headers, m.Payload)
}
func (m *Hmsg) Parse(payload []byte, offset int, messageType protocol.MessageType, streamBuffer *buffer.StreamBuffer) protocol.ParseResult {
	// HMSG <subject> <sid> [reply-to] <#header bytes> <#total bytes>␍␊[headers]␍␊␍␊[payload]␍␊
	common.ProtocolParserLog.Debugf("NATS Parse Hmsg:%d, %d, %x", offset, len(payload), string(payload))

	packetLen := readLine(payload)
	if packetLen < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) < 5 || len(parts) > 6 {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	// if strings.ToUpper(string(parts[0])) != "HMSG" {
	// 	return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen}
	// }

	msg := Hmsg{}
	msg.Subject = string(parts[1])
	msg.Sid = string(parts[2])

	index := 3
	if len(parts) == 6 {
		msg.ReplyTo = string(parts[3])
		index++
	}

	headerSize, err_1 := strconv.Atoi(string(parts[index]))
	totalSize, err_2 := strconv.Atoi(string(parts[index+1]))
	if err_1 != nil || err_2 != nil || headerSize > totalSize {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}

	packetEnd := packetLen + totalSize + len(_CRLF_)
	if len(payload) < packetEnd {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	if !bytes.HasSuffix(payload[:packetLen+headerSize], []byte(_CRLF_)) || !bytes.HasPrefix(payload[packetLen+totalSize:], []byte(_CRLF_)) {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}

	msg.HeaderSize = headerSize
	msg.PayloadSize = totalSize - headerSize

	headerVersionLen := readLine(payload[packetLen:])
	msg.HeaderVersion = string(payload[packetLen : packetLen+headerVersionLen-len(_CRLF_)])

	msg.Headers = make(map[string][]string)
	headerLines := bytes.Split(payload[packetLen+headerVersionLen:packetLen+headerSize], []byte(_CRLF_))
	for _, line := range headerLines {
		if len(line) == 0 {
			continue
		}
		parts := bytes.SplitN(line, []byte(":"), 2)
		if len(parts) != 2 {
			continue
		}
		key := string(bytes.TrimSpace(parts[0]))
		value := string(bytes.TrimSpace(parts[1]))

		if _, ok := msg.Headers[key]; !ok {
			msg.Headers[key] = []string{}
		}
		msg.Headers[key] = append(msg.Headers[key], value)
	}

	msg.Payload = payload[packetLen+headerSize : packetLen+totalSize]

	msg.ProtocolCode = HMSG
	msg.isReq = false
	msg.NatsMessage.Subject = msg.Subject
	msg.Buf = payload[:packetEnd]
	common.ProtocolParserLog.Debugf("NATS Parsed Hmsg:[%v], ReadBytes:%d, %v, %v", msg.String(), packetEnd, messageType, msg.isReq)
	if ok := msg.packFrameBase(streamBuffer, packetEnd+offset); !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetEnd + offset}
	}
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&msg},
		ReadBytes:      packetEnd + offset,
	}
}

// Ping
func (m *Ping) String() string {
	return "Protocol:PING"
}
func (m *Ping) Parse(payload []byte, offset int, messageType protocol.MessageType, streamBuffer *buffer.StreamBuffer) protocol.ParseResult {
	// PING␍␊
	common.ProtocolParserLog.Debugf("NATS Parse Ping:%d, %d, %x", offset, len(payload), string(payload))

	packetLen := readLine(payload)
	if packetLen < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	if packetLen < 6 {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	// if !strings.HasPrefix(strings.ToUpper(string(payload[:4])), "PING") {
	// 	return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen}
	// }

	msg := Ping{}

	packetEnd := packetLen
	msg.ProtocolCode = PING
	msg.isReq = true
	msg.Buf = payload[:packetLen]
	common.ProtocolParserLog.Debugf("NATS Parsed Ping:[%v], ReadBytes:%d, %v, %v", msg.String(), packetEnd, messageType, msg.isReq)
	if ok := msg.packFrameBase(streamBuffer, packetEnd+offset); !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetEnd + offset}
	}
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&msg},
		ReadBytes:      packetEnd + offset,
	}
}

// Pong
func (m *Pong) String() string {
	return "Protocol:PONG"
}
func (m *Pong) Parse(payload []byte, offset int, messageType protocol.MessageType, streamBuffer *buffer.StreamBuffer) protocol.ParseResult {
	// PONG␍␊
	common.ProtocolParserLog.Debugf("NATS Parse Pong:%d, %d, %x", offset, len(payload), string(payload))

	packetLen := readLine(payload)
	if packetLen < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	if packetLen < 6 {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	// if !strings.HasPrefix(strings.ToUpper(string(payload[:4])), "PONG") {
	// 	return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen}
	// }

	msg := Pong{}

	packetEnd := packetLen
	msg.ProtocolCode = PONG
	msg.isReq = false
	msg.Buf = payload[:packetEnd]
	common.ProtocolParserLog.Debugf("NATS Parsed Pong:[%v], ReadBytes:%d, %v, %v", msg.String(), packetEnd, messageType, msg.isReq)
	if ok := msg.packFrameBase(streamBuffer, packetEnd+offset); !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetEnd + offset}
	}
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&msg},
		ReadBytes:      packetEnd + offset,
	}
}

// Ok
func (m *Ok) String() string {
	return "Protocol:+OK"
}
func (m *Ok) Parse(payload []byte, offset int, messageType protocol.MessageType, streamBuffer *buffer.StreamBuffer) protocol.ParseResult {
	// +OK␍␊
	common.ProtocolParserLog.Debugf("NATS Parse Ok:%d, %d, %x", offset, len(payload), string(payload))

	packetLen := readLine(payload)
	if packetLen < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	if packetLen < 5 {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	// if !strings.HasPrefix(strings.ToUpper(string(payload[:3])), "+OK") {
	// 	return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen}
	// }

	msg := Ok{}

	packetEnd := packetLen
	msg.ProtocolCode = OK
	msg.isReq = false
	msg.Buf = payload[:packetEnd]
	common.ProtocolParserLog.Debugf("NATS Parsed Ok:[%v], ReadBytes:%d, %v, %v", msg.String(), packetEnd, messageType, msg.isReq)
	if ok := msg.packFrameBase(streamBuffer, packetEnd+offset); !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetEnd + offset}
	}
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&msg},
		ReadBytes:      packetEnd + offset,
	}
}

// Err
func (m *Err) String() string {
	return fmt.Sprintf("Protocol:-ERR,ErrorMessage:%v", m.ErrorMessage)
}
func (m *Err) Parse(payload []byte, offset int, messageType protocol.MessageType, streamBuffer *buffer.StreamBuffer) protocol.ParseResult {
	// -ERR <error message>␍␊
	common.ProtocolParserLog.Debugf("NATS Parse Err:%d, %d, %x", offset, len(payload), string(payload))

	packetLen := readLine(payload)
	if packetLen < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	if packetLen < 6 {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen + offset}
	}
	// if !strings.HasPrefix(strings.ToUpper(string(payload[:4])), "-ERR") {
	// 	return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetLen}
	// }

	msg := Err{}
	msg.ErrorMessage = string(trimFiled(payload[5 : packetLen-len(_CRLF_)]))

	packetEnd := packetLen
	msg.ProtocolCode = ERR
	msg.isReq = false
	msg.Buf = payload[:packetEnd]
	common.ProtocolParserLog.Debugf("NATS Parsed Err:[%v], ReadBytes:%d, %v, %v", msg.String(), packetEnd, messageType, msg.isReq)
	if ok := msg.packFrameBase(streamBuffer, packetEnd+offset); !ok {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: packetEnd + offset}
	}
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&msg},
		ReadBytes:      packetEnd + offset,
	}
}
