package mongodb

import (
	"encoding/json"
	"fmt"
	"kyanos/agent/buffer"
	. "kyanos/agent/protocol"
	"kyanos/bpf"

	"go.mongodb.org/mongo-driver/bson"
)

var _ ProtocolStreamParser = &MongoDBStreamParser{}
var _ ParsedMessage = &MongoDBFrame{}

type MongoDBFrame struct {
	FrameBase
	// Message Header Fields
	// Length of the mongodb header and the wire protocol data.
	length     int32
	requestId  int32
	responseTo int32
	opCode     int32

	// OP_MSG Fields
	// Relevant flag bits
	checksumPresent bool
	moreToCome      bool
	exhaustAllowed  bool
	sections        []Section
	opMsgType       string
	frame_body      string
	checksum        uint32
	isHandshake     bool
	consumed        bool

	cmd   int32
	isReq bool
}

// FormatToSummaryString implements protocol.ParsedMessage.
func (m *MongoDBFrame) FormatToSummaryString() string {
	return fmt.Sprintf("MongoDB base=[%s]", m.FrameBase.String())
}

// FormatToString implements protocol.ParsedMessage.
func (m *MongoDBFrame) FormatToString() string {
	return fmt.Sprintf("MongoDB base=[%s]", m.FrameBase.String())
}

// IsReq implements protocol.ParsedMessage.
func (m *MongoDBFrame) IsReq() bool {
	return false
}

type MongoDBStreamParser struct {
}

func (m *MongoDBStreamParser) ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult {
	result := ParseResult{}
	if messageType != Request && messageType != Response {
		result.ParseState = Invalid
		return result
	}

	head := streamBuffer.Head().Buffer()
	decoder := NewBinaryDecoder(head)

	if uint8(len(head)) < kHeaderLength {
		result.ParseState = NeedsMoreData
		return result
	}

	// Get the length of the packet. This length contains the size of the field containing the
	// message's length itself.
	length, err := ExtractLEInt[int32](decoder)
	if err != nil {
		result.ParseState = Invalid
		return result
	}
	if int32(len(head)) < length-int32(kMessageLengthSize) {
		result.ParseState = NeedsMoreData
		return result
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
		decoder.RemovePrefix(length) // int32
		result.ParseState = Ignore
		return result
	}

	mongoDBFrame := &MongoDBFrame{
		length:     length,
		requestId:  requestId,
		responseTo: respondTo,
		opCode:     opCode,
	}

	result.ParseState = ProcessPayload(decoder, mongoDBFrame)
	result.ReadBytes = decoder.ReadBytes()
	result.ParsedMessages = []ParsedMessage{mongoDBFrame}
	return result
}

func (m *MongoDBStreamParser) FindBoundary(streamBuffer *buffer.StreamBuffer, messageType MessageType, startPos int) int {
	// 待实现
	return 0
}

func (m *MongoDBStreamParser) Match(reqStream *[]ParsedMessage, respStream *[]ParsedMessage) []Record {
	// 待实现
	records := make([]Record, 0)
	return records
}

func init() {
	ParsersMap[bpf.AgentTrafficProtocolTKProtocolMongo] = func() ProtocolStreamParser {
		return &MongoDBStreamParser{}
	}
}

func ProcessPayload(decoder *BinaryDecoder, mongoDBFrame *MongoDBFrame) ParseState {
	switch mongoDBFrame.opCode {
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
	mongoDBFrame.checksumPresent = (flagBits & kChecksumBitmask) == kChecksumBitmask
	mongoDBFrame.moreToCome = (flagBits & kMoreToComeBitmask) == kMoreToComeBitmask
	mongoDBFrame.exhaustAllowed = (flagBits & kExhaustAllowedBitmask) == kExhaustAllowedBitmask
	if flagBits&kRequiredUnsetBitmask != 0 {
		return Invalid
	}

	// Determine the number of checksum bytes in the buffer.
	var checksumBytes int32
	if mongoDBFrame.checksumPresent {
		checksumBytes = 4
	} else {
		checksumBytes = 0
	}

	// Get the section(s) data from the buffer.
	allSectionsLength := mongoDBFrame.length - int32(kHeaderAndFlagSize) - int32(checksumBytes)
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
			section.length, err = ExtractLEInt[int32](decoder) //pixie uint32?
			if err != nil {
				return Invalid
			}
			if section.length < int32(kSectionLengthSize) {
				return Invalid
			}
			// Get the sequence identifier (command argument).
			seqIdentifier, err := decoder.ExtractStringUntil("\\0") //pixie '\0'?
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
				section.documents = append(section.documents, "")
				remainingSectionLength -= documentLength
				continue
			}

			// Convert the BSON document to a JSON string.
			var bsonDoc bson.M
			if err := bson.Unmarshal([]byte(sectionBody), &bsonDoc); err != nil {
				return Invalid
			}
			jsonDoc, err := bson.MarshalExtJSON(bsonDoc, true, false)
			if err != nil {
				return Invalid
			}

			var doc map[string]interface{}
			if err := json.Unmarshal(jsonDoc, &doc); err != nil {
				return Invalid
			}

			// Find the type of command argument from the kind 0 section.
			if section.kind == kSectionKindZero {
				var opMsgType string
				for key := range doc {
					opMsgType = key
					break
				}
				switch opMsgType {
				case kInsert, kDelete, kUpdate, kFind, kCursor:
					mongoDBFrame.opMsgType = opMsgType
				case kHello, kIsMaster, kIsMasterAlternate:
					// The frame is a handshaking message.
					mongoDBFrame.opMsgType = opMsgType
					mongoDBFrame.isHandshake = true
				default:
					// The frame is a response message, find the "ok" key and its value.
					if okValue, ok := doc["ok"]; ok {
						switch v := okValue.(type) {
						case map[string]interface{}:
							for key, value := range v {
								mongoDBFrame.opMsgType = fmt.Sprintf("ok: {%s: %v}", key, value)
								break
							}
						case float64:
							mongoDBFrame.opMsgType = fmt.Sprintf("ok: %d", int(v))
						}
					} else {
						return Invalid
					}

				}
			}

			section.documents = append(section.documents, string(jsonDoc))
			remainingSectionLength -= documentLength
		}
		mongoDBFrame.sections = append(mongoDBFrame.sections, section)
		allSectionsLength -= (section.length + int32(kSectionKindSize))
	}
	// Get the checksum data, if necessary.
	if mongoDBFrame.checksumPresent {
		mongoDBFrame.checksum, err = ExtractLEInt[uint32](decoder)
		if err != nil {
			return Invalid
		}
	}
	return Success
}
