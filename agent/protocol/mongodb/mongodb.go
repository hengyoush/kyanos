package mongodb

import (
	"encoding/json"
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	. "kyanos/agent/protocol"
	"kyanos/bpf"

	"go.mongodb.org/mongo-driver/bson"
)

var _ ProtocolStreamParser = &MongoDBStreamParser{}
var _ ParsedMessage = &MongoDBFrame{}

type MongoDBFilter struct {
}

// Filter implements protocol.ProtocolFilter.
func (m *MongoDBFilter) Filter(req ParsedMessage, resp ParsedMessage) bool {
	return true
}

// FilterByProtocol implements protocol.ProtocolFilter.
func (m *MongoDBFilter) FilterByProtocol(p bpf.AgentTrafficProtocolT) bool {
	return p == bpf.AgentTrafficProtocolTKProtocolMongo
}

// FilterByRequest implements protocol.ProtocolFilter.
func (m *MongoDBFilter) FilterByRequest() bool {
	return true
}

// FilterByResponse implements protocol.ProtocolFilter.
func (m *MongoDBFilter) FilterByResponse() bool {
	return true
}

var _ protocol.ProtocolFilter = &MongoDBFilter{}

func NewMongoDBFilter() *MongoDBFilter {
	return &MongoDBFilter{}
}

type MongoDBFrame struct {
	FrameBase
	// Message Header Fields
	// Length of the mongodb header and the wire protocol data.
	Length     int32
	RequestId  int32
	ResponseTo int32
	OpCode     int32

	// OP_MSG Fields
	// Relevant flag bits
	ChecksumPresent bool
	MoreToCome      bool
	ExhaustAllowed  bool
	Sections        []Section
	OpMsgType       string
	Frame_body      string
	Checksum        uint32
	IsHandshake     bool
	Consumed        bool
	isReq           bool
}

// FormatToString implements protocol.ParsedMessage.
func (m *MongoDBFrame) FormatToString() string {
	return fmt.Sprintf("MongoDB base=[%s]  Msg=[%s]", m.FrameBase.String(), m.Frame_body)
}

// IsReq implements protocol.ParsedMessage.
func (m *MongoDBFrame) IsReq() bool {
	return m.isReq
}

func (m *MongoDBFrame) SetReq(req bool) {
	m.isReq = req
}

func (m *MongoDBFrame) StreamId() StreamId {
	if m.ResponseTo == 0 {
		return StreamId(m.RequestId)
	}
	return StreamId(m.ResponseTo)
}

func (m *MongoDBFrame) ByteSize() int {
	return int(m.Length)
}

type MongoDBStreamParser struct {
	*State
}

func (m *MongoDBStreamParser) ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult {
	// seq := streamBuffer.Head().LeftBoundary()
	// ts, ok := streamBuffer.FindTimestampBySeq(seq)
	// if !ok {
	// 	return ParseResult{
	// 		ParseState: Invalid,
	// 	}
	// }

	result := ParseResult{}
	if messageType != Request && messageType != Response {
		result.ParseState = Invalid
		return result
	}

	buf := streamBuffer.Head().Buffer()
	decoder := NewBinaryDecoder(buf)

	nowHeaderLength := decoder.GetSize()

	if nowHeaderLength < int(kHeaderLength) {
		result.ParseState = NeedsMoreData
		return result
	}

	// Get the length of the packet. This length contains the size of the field containing the
	// message's length itself.
	length := LEndianBytesToInt[int32](decoder)

	if int32(decoder.GetSize()) < length {
		result.ParseState = NeedsMoreData
		return result
	} else {
		// Remove the kMessageLengthSize from the buffer.
		ExtractLEInt[int32](decoder)
	}

	// Get the Request ID.
	requestId, err := ExtractLEInt[int32](decoder)
	if err != nil {
		result.ParseState = Invalid
		return result
	}
	// Get the Response To.
	respondTo, err := ExtractLEInt[int32](decoder)
	if err != nil {
		result.ParseState = Invalid
		return result
	}
	// Get the message's op code (type).
	opCode, err := ExtractLEInt[int32](decoder)
	if err != nil {
		result.ParseState = Invalid
		return result
	}
	if !(opCode == kOPMsg || opCode == kOPReply ||
		opCode == kOPUpdate || opCode == kOPInsert ||
		opCode == kReserved || opCode == kOPQuery ||
		opCode == kOPGetMore || opCode == kOPDelete ||
		opCode == kOPKillCursors || opCode == kOPCompressed) {
		result.ParseState = Invalid
		return result
	}

	// Parser will ignore Op Codes that have been deprecated/removed from version 5.0 onwards as well
	// as kOPCompressed and kReserved which are not supported by the parser yet.
	if opCode != kOPMsg {
		decoder.RemovePrefix(length - 16)
		result.ReadBytes = int(length)
		result.ParseState = Ignore
		return result
	}

	// frameBase := FrameBase{}
	// frameBase.SetTimeStamp(ts)
	mongoDBFrame := &MongoDBFrame{
		Length:     length,
		RequestId:  requestId,
		ResponseTo: respondTo,
		OpCode:     opCode,
		isReq:      messageType == Request,
	}

	result.ParseState = ProcessPayload(decoder, mongoDBFrame)
	result.ReadBytes = decoder.ReadBytes()
	frameBase, ok := CreateFrameBase(streamBuffer, result.ReadBytes)
	if !ok {
		return ParseResult{
			ParseState: Invalid,
		}
	}
	if frameBase.ByteSize() != int(mongoDBFrame.Length) {
		//log.Printf("Frame length mismatch: %d != %d", frameBase.ByteSize(), mongoDBFrame.Length)
	}
	mongoDBFrame.FrameBase = frameBase

	result.ParsedMessages = []ParsedMessage{mongoDBFrame}
	if messageType == Request {
		m.State.StreamOrder = append(m.State.StreamOrder, StreamOrderPair{
			StreamId:  int32(requestId),
			Processed: false,
		})
	}
	return result
}

func (m *MongoDBStreamParser) FindBoundary(streamBuffer *buffer.StreamBuffer, messageType MessageType, startPos int) int {
	// TODO
	if startPos == 0 {
		return 0
	} else {
		return streamBuffer.Head().Len()
	}

}

func (m *MongoDBStreamParser) Match(reqStreams map[StreamId]*ParsedMessageQueue, respStreams map[StreamId]*ParsedMessageQueue) []Record {
	if len(reqStreams) == 0 || len(respStreams) == 0 {
		return []Record{}
	}

	records := make([]Record, 0)
	var errorCount int = 0

	for i := range m.State.StreamOrder {
		streamIdPair := &m.State.StreamOrder[i]
		streamId := streamIdPair.StreamId
		respDeque, respExists := respStreams[StreamId(streamId)]
		if !respExists {
			continue
		}
		reqDeque, reqExists := reqStreams[StreamId(streamId)]
		if !reqExists {
			continue
		}
		latestRespTs := uint64(0)
		for i := range *respDeque {
			respFrame := (*respDeque)[i].(*MongoDBFrame)
			if respFrame.Consumed {
				continue
			}
			latestRespTs = respFrame.TimestampNs()

			// Find corresponding request frame
			var reqFrame *MongoDBFrame
			for j := len(*reqDeque) - 1; j >= 0; j-- {
				if (*reqDeque)[j].TimestampNs() <= latestRespTs {
					reqFrame = (*reqDeque)[j].(*MongoDBFrame)
					break
				}
			}

			if reqFrame == nil || reqFrame.TimestampNs() > latestRespTs {
				//log.Printf("Did not find a request frame that is earlier than the response. Response's responseTo: %d", respFrame.ResponseTo)
				respFrame.Consumed = true
				errorCount++
				break
			}

			FindMoreToComeResponses(respStreams, &errorCount, respFrame, &latestRespTs)

			// Stitch the request/response and add it to records
			reqFrame.Consumed = true
			respFrame.Consumed = true
			FlattenSections(reqFrame)
			FlattenSections(respFrame)

			// if reqFrame.isHandshake || respFrame.isHandshake {
			// 	reqFrame.consumed = true
			// 	respFrame.consumed = true
			// 	break
			// }

			records = append(records, Record{Req: reqFrame, Resp: respFrame, ResponseStatus: SuccessStatus})
			break
		}

		// Clean up consumed requests
		eraseUntilIndex := 0
		for eraseUntilIndex < len(*reqDeque) {
			reqFrame := (*reqDeque)[eraseUntilIndex].(*MongoDBFrame)
			if !(reqFrame.Consumed || reqFrame.TimestampNs() < latestRespTs) {
				break
			}
			if !reqFrame.Consumed {
				errorCount++
			}
			eraseUntilIndex++
		}

		*reqDeque = (*reqDeque)[eraseUntilIndex:]
		if len(*reqDeque) == 0 {
			delete(reqStreams, StreamId(streamId))
		}
		streamIdPair.Processed = true
	}

	// Clear the response deques
	for streamId, respDeque := range respStreams {
		for _, resp := range *respDeque {
			respFrame := resp.(*MongoDBFrame)
			if !respFrame.Consumed {
				errorCount++
			}
		}
		delete(respStreams, streamId)
	}

	// Clear the state
	for i := len(m.State.StreamOrder) - 1; i >= 0; i-- {
		if m.State.StreamOrder[i].Processed {
			m.State.StreamOrder = append(m.State.StreamOrder[:i], m.State.StreamOrder[i+1:]...)
		}
	}

	// return RecordsWithErrorCount{Records: records, ErrorCount: errorCount}
	return records
}

func init() {
	ParsersMap[bpf.AgentTrafficProtocolTKProtocolMongo] = func() ProtocolStreamParser {
		return &MongoDBStreamParser{
			State: &State{
				StreamOrder: make([]StreamOrderPair, 0),
			},
		}
	}
}

func ProcessPayload(decoder *BinaryDecoder, mongoDBFrame *MongoDBFrame) ParseState {
	switch mongoDBFrame.OpCode {
	case kOPMsg:
		return ProcessOpMsg(decoder, mongoDBFrame)
	case kOPCompressed:
		return Ignore
	case kReserved:
		return Ignore
	default:
		return Invalid
	}
}

func ProcessOpMsg(decoder *BinaryDecoder, mongoDBFrame *MongoDBFrame) ParseState {
	flagBits, err := ExtractLEInt[uint32](decoder)
	if err != nil {
		return Invalid
	}

	// Find relevant flag bit information and ensure remaining bits are not set.
	// Bits 0-15 are required and bits 16-31 are optional.
	mongoDBFrame.ChecksumPresent = (flagBits & kChecksumBitmask) == kChecksumBitmask
	mongoDBFrame.MoreToCome = (flagBits & kMoreToComeBitmask) == kMoreToComeBitmask
	mongoDBFrame.ExhaustAllowed = (flagBits & kExhaustAllowedBitmask) == kExhaustAllowedBitmask
	if flagBits&kRequiredUnsetBitmask != 0 {
		return Invalid
	}

	// Determine the number of checksum bytes in the buffer.
	var checksumBytes int32
	if mongoDBFrame.ChecksumPresent {
		checksumBytes = 4
	} else {
		checksumBytes = 0
	}

	// Get the section(s) data from the buffer.
	allSectionsLength := mongoDBFrame.Length - int32(kHeaderAndFlagSize) - int32(checksumBytes)
	for allSectionsLength > 0 {
		var section Section
		section.kind, err = ExtractLEInt[uint8](decoder)
		if err != nil {
			return Invalid
		}
		// Length of the current section still remaining in the buffer.
		var remainingSectionLength int32 = 0

		if section.kind == kSectionKindZero {
			// Check the length but don't extract it since the later logic requires the buffer to retain it.
			section.length = LEndianBytesToInt[int32](decoder)
			if section.length < int32(kSectionLengthSize) {
				return Invalid
			}
			remainingSectionLength = section.length
		} else if section.kind == kSectionKindOne {
			section.length, err = ExtractLEInt[int32](decoder)
			if err != nil {
				return Invalid
			}
			if section.length < int32(kSectionLengthSize) {
				return Invalid
			}
			// Get the sequence identifier (command argument).
			seqIdentifier, err := decoder.ExtractStringUntil("\x00")
			if err != nil {
				return Invalid
			}
			// Make sure the sequence identifier is a valid OP_MSG kind 1 command argument.
			if seqIdentifier != "documents" && seqIdentifier != "updates" && seqIdentifier != "deletes" {
				return Invalid
			}
			remainingSectionLength = section.length - int32(kSectionLengthSize) - int32(len(seqIdentifier)) - int32(kSectionKindSize)
		} else {
			return Invalid
		}

		// Extract the document(s) from the section and convert it from type BSON to a JSON string.
		for remainingSectionLength > 0 {
			// We can't extract the length bytes since bson_new_from_data() expects those bytes in
			// the data as well as the expected length in another parameter.
			documentLength := LEndianBytesToInt[int32](decoder)
			if documentLength > kMaxBSONObjSize {
				return Invalid
			}
			sectionBody, err := decoder.ExtractString(int(documentLength))
			if err != nil {
				return Invalid
			}

			// Check if section_body contains an empty document.
			if len(sectionBody) == int(kSectionLengthSize) {
				section.Documents = append(section.Documents, "")
				remainingSectionLength -= documentLength
				continue
			}

			// Convert the BSON document to a JSON string.
			var bsonDoc bson.D
			if err := bson.Unmarshal([]byte(sectionBody), &bsonDoc); err != nil {
				return Invalid
			}
			jsonDoc, err := bson.MarshalExtJSON(bsonDoc, true, false)
			if err != nil {
				return Invalid
			}

			// Find the type of command argument from the kind 0 section.
			if section.kind == kSectionKindZero {
				var doc map[string]interface{}
				if err := json.Unmarshal(jsonDoc, &doc); err != nil {
					return Invalid
				}

				var opMsgType string
				for _, element := range bsonDoc {
					opMsgType = element.Key
					break
				}
				switch opMsgType {
				case kInsert, kDelete, kUpdate, kFind, kCursor:
					mongoDBFrame.OpMsgType = opMsgType
				case kHello, kIsMaster, kIsMasterAlternate:
					// The frame is a handshaking message.
					mongoDBFrame.OpMsgType = opMsgType
					mongoDBFrame.IsHandshake = true
				default:
					// The frame is a response message, find the "ok" key and its value.
					if okValue, ok := doc["ok"]; ok {
						switch v := okValue.(type) {
						case map[string]interface{}:
							for key, value := range v {
								mongoDBFrame.OpMsgType = fmt.Sprintf("ok: {%s: %v}", key, value)
								break
							}
						case float64:
							mongoDBFrame.OpMsgType = fmt.Sprintf("ok: %d", int(v))
						}
					} else {
						return Invalid
					}

				}
			}

			section.Documents = append(section.Documents, string(jsonDoc))
			remainingSectionLength -= documentLength
		}
		mongoDBFrame.Sections = append(mongoDBFrame.Sections, section)
		allSectionsLength -= (section.length + int32(kSectionKindSize))
	}
	// Get the checksum data, if necessary.
	if mongoDBFrame.ChecksumPresent {
		mongoDBFrame.Checksum, err = ExtractLEInt[uint32](decoder)
		if err != nil {
			return Invalid
		}
	}
	return Success
}

func NewMongoDBStreamParser() *MongoDBStreamParser {
	return &MongoDBStreamParser{
		State: &State{
			StreamOrder: make([]StreamOrderPair, 0),
		},
	}
}
