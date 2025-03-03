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

	// PUB,HPUB/MSG,HMSG;PING/PONG
	for _, id := range []protocol.StreamId{0, 1} {
		if records_ := match(reqStreams, respStreams, id); len(records_) > 0 {
			records = append(records, records_...)
		}
	}
	// Other
	clear(reqStreams, respStreams, 2)
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
func clear(reqStreams map[protocol.StreamId]*protocol.ParsedMessageQueue, respStreams map[protocol.StreamId]*protocol.ParsedMessageQueue, id protocol.StreamId) {
	if reqStream, ok := reqStreams[id]; ok {
		*reqStream = (*reqStream)[:0]
	}
	if respStream, ok := respStreams[id]; ok {
		*respStream = (*respStream)[:0]
	}
}

func (parser *NatsStreamParser) FindBoundary(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType, startPos int) int {
	buffer := streamBuffer.Head().Buffer()
	stream := strings.ToUpper(string(buffer[startPos:]))

	boundary := -1
	for key, parser := range natsParsersMap {
		if index := strings.Index(stream, key); index >= 0 {
			if parser().CheckBoundary(stream, index+len(key)) {
				boundary = startPos + index
				break
			} else {
				continue
			}
		}
	}
	common.ProtocolParserLog.Debugf("NATSStreamParser FindBoundary: %d, %s", boundary, stream)
	return boundary
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
	offset := index - len(method)
	msg, parsedLen := natsParser.Parse(buffer[offset:], messageType)
	if parsedLen < 0 {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}
	if msg == nil {
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: parsedLen + offset}
	}
	return msg.packFrameBase(streamBuffer, parsedLen+offset)
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
	switch msg.ProtocolCode {
	case MSG, HMSG, PUB, HPUB:
		return 0
	case PING, PONG:
		return 1
	default:
		return 2
	}
}

func (msg *NatsMessage) packFrameBase(streamBuffer *buffer.StreamBuffer, readBytes int) protocol.ParseResult {
	fb, ok := protocol.CreateFrameBase(streamBuffer, readBytes)
	if !ok {
		common.ProtocolParserLog.Debugf("NATS Failed to create FrameBase for frameSize=%d", readBytes)
		return protocol.ParseResult{ParseState: protocol.Ignore, ReadBytes: readBytes}
	}
	msg.FrameBase = fb
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{msg},
		ReadBytes:      readBytes,
	}
}

// Info
func (m *Info) String() string {
	return fmt.Sprintf("Protocol:INFO,ServerID:%v,ServerName:%v,Version:%v,GoVersion:%v,Host:%v,Port:%v,MaxPayload:%v,TLSRequired:%v",
		m.ServerID, m.ServerName, m.Version, m.GoVersion, m.Host, m.Port, m.MaxPayload, m.TLSRequired)
}
func (m *Info) CheckBoundary(stream string, pos int) bool {
	return len(stream) > pos && (stream[pos] == ' ' || stream[pos] == '\t')
}
func (m *Info) ParseData(payload []byte) (*Info, int) {
	// INFO {"option_name":option_value,...}␍␊
	packetLen := readLine(payload)
	if packetLen < 0 {
		return nil, -1
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) != 2 {
		return nil, packetLen
	}

	msg := Info{}
	err := json.Unmarshal(parts[1], &msg)
	if err != nil {
		return nil, packetLen
	}

	msg.ProtocolCode = INFO
	msg.isReq = false
	msg.Buf = payload[:packetLen]
	return &msg, packetLen
}
func (m *Info) Parse(payload []byte, messageType protocol.MessageType) (*NatsMessage, int) {
	common.ProtocolParserLog.Debugf("NATS Parse Info:%d, %x", len(payload), string(payload))
	msg, parsedLen := m.ParseData(payload)
	if parsedLen < 0 || msg == nil {
		return nil, parsedLen
	}
	common.ProtocolParserLog.Debugf("NATS Parsed Info:[%v], ReadBytes:%d", msg.String(), parsedLen)
	return &msg.NatsMessage, parsedLen
}

// Connect
func (m *Connect) String() string {
	return fmt.Sprintf("Protocol:CONNECT,Verbose:%v,Pedantic:%v,TLSRequired:%v,Name:%v,Version:%v",
		m.Verbose, m.Pedantic, m.TLSRequired, m.Name, m.Version)
}
func (m *Connect) CheckBoundary(stream string, pos int) bool {
	return len(stream) > pos && (stream[pos] == ' ' || stream[pos] == '\t')
}
func (m *Connect) ParseData(payload []byte) (*Connect, int) {
	// CONNECT {"option_name":option_value,...}␍␊
	packetLen := readLine(payload)
	if packetLen < 0 {
		return nil, -1
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) != 2 {
		return nil, packetLen
	}

	msg := Connect{}
	err := json.Unmarshal(parts[1], &msg)
	if err != nil {
		return nil, packetLen
	}

	msg.ProtocolCode = CONNECT
	msg.isReq = true
	msg.Buf = payload[:packetLen]
	return &msg, packetLen
}

func (m *Connect) Parse(payload []byte, messageType protocol.MessageType) (*NatsMessage, int) {
	common.ProtocolParserLog.Debugf("NATS Parse Connect:%d, %x", len(payload), string(payload))
	msg, parsedLen := m.ParseData(payload)
	if parsedLen < 0 || msg == nil {
		return nil, parsedLen
	}
	common.ProtocolParserLog.Debugf("NATS Parsed Connect:[%v], ReadBytes:%d", msg.String(), parsedLen)
	return &msg.NatsMessage, parsedLen
}

// Pub
func (m *Pub) String() string {
	return fmt.Sprintf("Protocol:PUB,Subject:%v,ReplyTo:%v,PayloadSize:%d,Payload:%x", m.Subject, m.ReplyTo, m.PayloadSize, m.Payload)
}
func (m *Pub) CheckBoundary(stream string, pos int) bool {
	return len(stream) > pos && (stream[pos] == ' ' || stream[pos] == '\t')
}
func (m *Pub) ParseData(payload []byte) (*Pub, int) {
	// PUB <subject> [reply-to] <#bytes>␍␊[payload]␍␊
	packetLen := readLine(payload)
	if packetLen < 0 {
		return nil, -1
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) < 3 || len(parts) > 4 {
		return nil, packetLen
	}

	msg := Pub{}
	msg.Subject = string(parts[1])

	index := 2
	if len(parts) == 4 {
		msg.ReplyTo = string(parts[index])
		index++
	}
	payloadSize, err := strconv.Atoi(string(parts[index]))
	if err != nil {
		return nil, packetLen
	}
	packetEnd := packetLen + payloadSize + len(_CRLF_)
	if len(payload) < packetEnd {
		return nil, packetLen
	}
	if !bytes.HasPrefix(payload[packetLen+payloadSize:], []byte(_CRLF_)) {
		return nil, packetLen
	}
	msg.PayloadSize = payloadSize
	msg.Payload = payload[packetLen : packetLen+payloadSize]

	msg.ProtocolCode = PUB
	msg.isReq = true
	msg.NatsMessage.Subject = msg.Subject
	msg.Buf = payload[:packetEnd]
	return &msg, packetEnd
}

func (m *Pub) Parse(payload []byte, messageType protocol.MessageType) (*NatsMessage, int) {
	common.ProtocolParserLog.Debugf("NATS Parse Pub:%d, %x", len(payload), string(payload))
	msg, parsedLen := m.ParseData(payload)
	if parsedLen < 0 || msg == nil {
		return nil, parsedLen
	}
	common.ProtocolParserLog.Debugf("NATS Parsed Pub:[%v], ReadBytes:%d", msg.String(), parsedLen)
	return &msg.NatsMessage, parsedLen
}

// Hpub
func (m *Hpub) String() string {
	return fmt.Sprintf("Protocol:HPUB,Subject:%v,ReplyTo:%v,HeaderSize:%d,PayloadSize:%d,HeaderVersion:%v,Headers:%v,Payload:%x",
		m.Subject, m.ReplyTo, m.HeaderSize, m.PayloadSize, m.HeaderVersion, m.Headers, m.Payload)
}
func (m *Hpub) CheckBoundary(stream string, pos int) bool {
	return len(stream) > pos && (stream[pos] == ' ' || stream[pos] == '\t')
}
func (m *Hpub) ParseData(payload []byte) (*Hpub, int) {
	// HPUB <subject> [reply-to] <#header bytes> <#total bytes>␍␊[headers]␍␊␍␊[payload]␍␊
	packetLen := readLine(payload)
	if packetLen < 0 {
		return nil, -1
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) < 4 || len(parts) > 5 {
		return nil, packetLen
	}

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
		return nil, packetLen
	}

	packetEnd := packetLen + totalSize + len(_CRLF_)
	if len(payload) < packetEnd {
		return nil, packetLen
	}
	if !bytes.HasSuffix(payload[:packetLen+headerSize], []byte(_CRLF_)) || !bytes.HasPrefix(payload[packetLen+totalSize:], []byte(_CRLF_)) {
		return nil, packetLen
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
		key, value, ok := strings.Cut(string(line), ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

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
	return &msg, packetEnd
}

func (m *Hpub) Parse(payload []byte, messageType protocol.MessageType) (*NatsMessage, int) {
	common.ProtocolParserLog.Debugf("NATS Parse Hpub:%d, %x", len(payload), string(payload))
	msg, parsedLen := m.ParseData(payload)
	if parsedLen < 0 || msg == nil {
		return nil, parsedLen
	}
	common.ProtocolParserLog.Debugf("NATS Parsed Hpub:[%v], ReadBytes:%d", msg.String(), parsedLen)
	return &msg.NatsMessage, parsedLen
}

// Sub
func (m *Sub) String() string {
	return fmt.Sprintf("Protocol:SUB,Subject:%v,QueueGroup:%v,Sid:%v",
		m.Subject, m.QueueGroup, m.Sid)
}
func (m *Sub) CheckBoundary(stream string, pos int) bool {
	return len(stream) > pos && (stream[pos] == ' ' || stream[pos] == '\t')
}
func (m *Sub) ParseData(payload []byte) (*Sub, int) {
	// SUB <subject> [queue group] <sid>␍␊
	packetLen := readLine(payload)
	if packetLen < 0 {
		return nil, -1
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) < 3 || len(parts) > 4 {
		return nil, packetLen
	}

	msg := Sub{}
	msg.Subject = string(parts[1])

	index := 2
	if len(parts) == 4 {
		msg.QueueGroup = string(parts[2])
		index++
	}
	msg.Sid = string(parts[index])

	msg.ProtocolCode = SUB
	msg.isReq = true
	msg.NatsMessage.Subject = msg.Subject
	msg.Buf = payload[:packetLen]
	return &msg, packetLen
}

func (m *Sub) Parse(payload []byte, messageType protocol.MessageType) (*NatsMessage, int) {
	common.ProtocolParserLog.Debugf("NATS Parse Sub:%d, %x", len(payload), string(payload))
	msg, parsedLen := m.ParseData(payload)
	if parsedLen < 0 || msg == nil {
		return nil, parsedLen
	}
	common.ProtocolParserLog.Debugf("NATS Parsed Sub:[%v], ReadBytes:%d", msg.String(), parsedLen)
	return &msg.NatsMessage, parsedLen
}

// Unsub
func (m *Unsub) String() string {
	return fmt.Sprintf("Protocol:UNSUB,Sid:%v,MaxMsgs:%v",
		m.Sid, m.MaxMsgs)
}
func (m *Unsub) CheckBoundary(stream string, pos int) bool {
	return len(stream) > pos && (stream[pos] == ' ' || stream[pos] == '\t')
}
func (m *Unsub) ParseData(payload []byte) (*Unsub, int) {
	// UNSUB <sid> [max_msgs]␍␊
	packetLen := readLine(payload)
	if packetLen < 0 {
		return nil, -1
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) < 2 || len(parts) > 3 {
		return nil, packetLen
	}

	msg := Unsub{}
	msg.Sid = string(parts[1])

	if len(parts) == 3 {
		maxMsgs, err := strconv.Atoi(string(parts[2]))
		if err != nil {
			return nil, packetLen
		}
		msg.MaxMsgs = maxMsgs
	}

	msg.ProtocolCode = UNSUB
	msg.isReq = true
	msg.Buf = payload[:packetLen]
	return &msg, packetLen
}

func (m *Unsub) Parse(payload []byte, messageType protocol.MessageType) (*NatsMessage, int) {
	common.ProtocolParserLog.Debugf("NATS Parse Unsub:%d, %x", len(payload), string(payload))
	msg, parsedLen := m.ParseData(payload)
	if parsedLen < 0 || msg == nil {
		return nil, parsedLen
	}
	common.ProtocolParserLog.Debugf("NATS Parsed Unsub:[%v], ReadBytes:%d", msg.String(), parsedLen)
	return &msg.NatsMessage, parsedLen
}

// Msg
func (m *Msg) String() string {
	return fmt.Sprintf("Protocol:MSG,Subject:%v,Sid:%v,ReplyTo:%v,PayloadSize:%d,Payload:%x",
		m.Subject, m.Sid, m.ReplyTo, m.PayloadSize, m.Payload)
}
func (m *Msg) CheckBoundary(stream string, pos int) bool {
	return len(stream) > pos && (stream[pos] == ' ' || stream[pos] == '\t')
}
func (m *Msg) ParseData(payload []byte) (*Msg, int) {
	// MSG <subject> <sid> [reply-to] <#bytes>␍␊[payload]␍␊
	packetLen := readLine(payload)
	if packetLen < 0 {
		return nil, -1
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) < 4 || len(parts) > 5 {
		return nil, packetLen
	}

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
		return nil, packetLen
	}
	packetEnd := packetLen + payloadSize + len(_CRLF_)
	if len(payload) < packetEnd {
		return nil, packetLen
	}
	if !bytes.HasPrefix(payload[packetLen+payloadSize:], []byte(_CRLF_)) {
		return nil, packetLen
	}
	msg.PayloadSize = payloadSize
	msg.Payload = payload[packetLen : packetLen+payloadSize]

	msg.ProtocolCode = MSG
	msg.isReq = false
	msg.NatsMessage.Subject = msg.Subject
	msg.Buf = payload[:packetEnd]
	return &msg, packetEnd
}

func (m *Msg) Parse(payload []byte, messageType protocol.MessageType) (*NatsMessage, int) {
	common.ProtocolParserLog.Debugf("NATS Parse Msg:%d, %x", len(payload), string(payload))
	msg, parsedLen := m.ParseData(payload)
	if parsedLen < 0 || msg == nil {
		return nil, parsedLen
	}
	common.ProtocolParserLog.Debugf("NATS Parsed Msg:[%v], ReadBytes:%d", msg.String(), parsedLen)
	return &msg.NatsMessage, parsedLen
}

// Hmsg
func (m *Hmsg) String() string {
	return fmt.Sprintf("Protocol:HMSG,Subject:%v,Sid:%v,ReplyTo:%v,HeaderSize:%d,PayloadSize:%d,HeaderVersion:%v,Headers:%v,Payload:%x",
		m.Subject, m.Sid, m.ReplyTo, m.HeaderSize, m.PayloadSize, m.HeaderVersion, m.Headers, m.Payload)
}
func (m *Hmsg) CheckBoundary(stream string, pos int) bool {
	return len(stream) > pos && (stream[pos] == ' ' || stream[pos] == '\t')
}
func (m *Hmsg) ParseData(payload []byte) (*Hmsg, int) {
	// HMSG <subject> <sid> [reply-to] <#header bytes> <#total bytes>␍␊[headers]␍␊␍␊[payload]␍␊
	packetLen := readLine(payload)
	if packetLen < 0 {
		return nil, -1
	}
	parts := splitFields(payload[:packetLen-len(_CRLF_)])
	if len(parts) < 5 || len(parts) > 6 {
		return nil, packetLen
	}

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
		return nil, packetLen
	}

	packetEnd := packetLen + totalSize + len(_CRLF_)
	if len(payload) < packetEnd {
		return nil, packetLen
	}
	if !bytes.HasSuffix(payload[:packetLen+headerSize], []byte(_CRLF_)) || !bytes.HasPrefix(payload[packetLen+totalSize:], []byte(_CRLF_)) {
		return nil, packetLen
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
		key, value, ok := strings.Cut(string(line), ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

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
	return &msg, packetEnd
}

func (m *Hmsg) Parse(payload []byte, messageType protocol.MessageType) (*NatsMessage, int) {
	common.ProtocolParserLog.Debugf("NATS Parse Hmsg:%d, %x", len(payload), string(payload))
	msg, parsedLen := m.ParseData(payload)
	if parsedLen < 0 || msg == nil {
		return nil, parsedLen
	}
	common.ProtocolParserLog.Debugf("NATS Parsed Hmsg:[%v], ReadBytes:%d", msg.String(), parsedLen)
	return &msg.NatsMessage, parsedLen
}

// Ping
func (m *Ping) String() string {
	return "Protocol:PING"
}
func (m *Ping) CheckBoundary(stream string, pos int) bool {
	return true
}
func (m *Ping) ParseData(payload []byte) (*Ping, int) {
	// PING␍␊
	packetLen := readLine(payload)
	if packetLen < 0 {
		return nil, -1
	}
	if packetLen < 6 {
		return nil, packetLen
	}

	msg := Ping{}

	msg.ProtocolCode = PING
	msg.isReq = true
	msg.Buf = payload[:packetLen]
	return &msg, packetLen
}

func (m *Ping) Parse(payload []byte, messageType protocol.MessageType) (*NatsMessage, int) {
	common.ProtocolParserLog.Debugf("NATS Parse Ping:%d, %x", len(payload), string(payload))
	msg, parsedLen := m.ParseData(payload)
	if parsedLen < 0 || msg == nil {
		return nil, parsedLen
	}
	common.ProtocolParserLog.Debugf("NATS Parsed Ping:[%v], ReadBytes:%d", msg.String(), parsedLen)
	return &msg.NatsMessage, parsedLen
}

// Pong
func (m *Pong) String() string {
	return "Protocol:PONG"
}
func (m *Pong) CheckBoundary(stream string, pos int) bool {
	return true
}
func (m *Pong) ParseData(payload []byte) (*Pong, int) {
	// PONG␍␊
	packetLen := readLine(payload)
	if packetLen < 0 {
		return nil, -1
	}
	if packetLen < 6 {
		return nil, packetLen
	}

	msg := Pong{}

	msg.ProtocolCode = PONG
	msg.isReq = false
	msg.Buf = payload[:packetLen]
	return &msg, packetLen
}

func (m *Pong) Parse(payload []byte, messageType protocol.MessageType) (*NatsMessage, int) {
	common.ProtocolParserLog.Debugf("NATS Parse Pong:%d, %x", len(payload), string(payload))
	msg, parsedLen := m.ParseData(payload)
	if parsedLen < 0 || msg == nil {
		return nil, parsedLen
	}
	common.ProtocolParserLog.Debugf("NATS Parsed Pong:[%v], ReadBytes:%d", msg.String(), parsedLen)
	return &msg.NatsMessage, parsedLen
}

// Ok
func (m *Ok) String() string {
	return "Protocol:+OK"
}
func (m *Ok) CheckBoundary(stream string, pos int) bool {
	return true
}
func (m *Ok) ParseData(payload []byte) (*Ok, int) {
	// +OK␍␊
	packetLen := readLine(payload)
	if packetLen < 0 {
		return nil, -1
	}
	if packetLen < 5 {
		return nil, packetLen
	}

	msg := Ok{}

	msg.ProtocolCode = OK
	msg.isReq = false
	msg.Buf = payload[:packetLen]
	return &msg, packetLen
}

func (m *Ok) Parse(payload []byte, messageType protocol.MessageType) (*NatsMessage, int) {
	common.ProtocolParserLog.Debugf("NATS Parse Ok:%d, %x", len(payload), string(payload))
	msg, parsedLen := m.ParseData(payload)
	if parsedLen < 0 || msg == nil {
		return nil, parsedLen
	}
	common.ProtocolParserLog.Debugf("NATS Parsed Ok:[%v], ReadBytes:%d", msg.String(), parsedLen)
	return &msg.NatsMessage, parsedLen
}

// Err
func (m *Err) String() string {
	return fmt.Sprintf("Protocol:-ERR,ErrorMessage:%v", m.ErrorMessage)
}
func (m *Err) CheckBoundary(stream string, pos int) bool {
	return len(stream) > pos && (stream[pos] == ' ' || stream[pos] == '\t')
}
func (m *Err) ParseData(payload []byte) (*Err, int) {
	// -ERR <error message>␍␊
	packetLen := readLine(payload)
	if packetLen < 0 {
		return nil, -1
	}
	if packetLen < 6 {
		return nil, packetLen
	}

	msg := Err{}
	msg.ErrorMessage = string(trimFiled(payload[5 : packetLen-len(_CRLF_)]))

	msg.ProtocolCode = ERR
	msg.isReq = false
	msg.Buf = payload[:packetLen]
	return &msg, packetLen
}

func (m *Err) Parse(payload []byte, messageType protocol.MessageType) (*NatsMessage, int) {
	common.ProtocolParserLog.Debugf("NATS Parse Err:%d, %x", len(payload), string(payload))
	msg, parsedLen := m.ParseData(payload)
	if parsedLen < 0 || msg == nil {
		return nil, parsedLen
	}
	common.ProtocolParserLog.Debugf("NATS Parsed Err:[%v], ReadBytes:%d", msg.String(), parsedLen)
	return &msg.NatsMessage, parsedLen
}
