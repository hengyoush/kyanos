package rocketmq

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"
	"strings"
	"time"
)

const (
	requestCodeOffset      = 0
	languageCodeOffset     = 2
	versionFlagOffset      = 3
	opaqueOffset           = 5
	requestFlagOffset      = 9
	remarkLengthOffset     = 13
	propertiesLengthOffset = 17

	serializationTypeJSON     = 0
	serializationTypeRocketMQ = 1

	requestTimeoutDuration = 5 * time.Minute
)

func init() {
	protocol.ParsersMap[bpf.AgentTrafficProtocolTKProtocolRocketMQ] = func() protocol.ProtocolStreamParser {
		return &RocketMQStreamParser{
			requestOpaqueMap: make(map[int32]struct{}),
		}
	}
}

func NewRocketMQMessage() *RocketMQMessage {
	return &RocketMQMessage{
		LanguageCode:  UNKNOWN_LANGUAGE,
		RemarkBuf:     make([]byte, 0),
		PropertiesBuf: make([]byte, 0),
		BodyBuf:       make([]byte, 0),
		Properties:    make(map[string]string),
	}
}

func (r *RocketMQMessage) FormatToString() string {
	remark := string(r.RemarkBuf)
	body := string(r.BodyBuf)

	propertiesMap := string(r.PropertiesBuf)
	if len(r.Properties) > 0 {
		props := make([]string, 0, len(r.Properties))
		for key, value := range r.Properties {
			props = append(props, fmt.Sprintf("%s=%s", key, value))
		}
		propertiesMap = fmt.Sprintf("{%s}", strings.Join(props, ", "))
	}

	return fmt.Sprintf("base=[%s] detail=[code=%d, language=%s, version=%d, opaque=%d, flag=%d, remark=%s, extFields=%s, body=%s]",
		r.FrameBase.String(),
		r.RequestCode,
		r.LanguageCode,
		r.VersionFlag,
		r.Opaque,
		r.RequestFlag,
		remark,
		propertiesMap,
		body,
	)

}

func (r *RocketMQMessage) IsReq() bool {
	return r.isReq
}

func (r *RocketMQStreamParser) ParseStream(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType) protocol.ParseResult {
	buffer := streamBuffer.Head().Buffer()
	common.ProtocolParserLog.Debugf("ParseStream received buffer length: %d", len(buffer))

	if len(buffer) < 8 {
		common.ProtocolParserLog.Debugf("Buffer too small for header, needs more data.")
		return protocol.ParseResult{
			ParseState: protocol.NeedsMoreData,
		}
	}

	frameSize := int(binary.BigEndian.Uint32(buffer[:4]))
	if frameSize <= 0 {
		common.ProtocolParserLog.Debugf("Invalid frame size: %d", frameSize)
		return protocol.ParseResult{ParseState: protocol.Invalid, ReadBytes: 4}
	}

	if frameSize+4 > len(buffer) {
		common.ProtocolParserLog.Debugf("Frame size %d exceeds buffer length %d, needs more data.", frameSize, len(buffer))
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	headerLength := binary.BigEndian.Uint32(buffer[4:8])
	headerDataLen := headerLength & 0xFFFFFF
	serializedType := byte((headerLength >> 24) & 0xFF)

	if 4+int(headerDataLen) > frameSize || len(buffer) < 8+int(headerDataLen) {
		common.ProtocolParserLog.Debugf("Incomplete header detected: headerDataLen=%d, frameSize=%d.", headerDataLen, frameSize)
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	headerBody := buffer[8 : 8+headerDataLen]

	message, err := r.parseHeader(headerBody, serializedType)
	if err != nil {
		common.ProtocolParserLog.Errorf("Failed to parse header: %v", err)
		return protocol.ParseResult{ParseState: protocol.Invalid, ReadBytes: int(frameSize)}
	}

	if frameSize > 4+int(headerDataLen) {
		body := buffer[8+headerDataLen : frameSize]
		message.BodyBuf = body
	}

	message.isReq = messageType == protocol.Request
	fb, ok := protocol.CreateFrameBase(streamBuffer, frameSize)

	if !ok {
		common.ProtocolParserLog.Debugf("Failed to create FrameBase for frameSize=%d", frameSize)
		return protocol.ParseResult{
			ParseState: protocol.Ignore,
			ReadBytes:  frameSize,
		}
	}

	common.ProtocolParserLog.Debugf("Successfully parsed message: %+v", message)
	message.FrameBase = fb
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ReadBytes:      frameSize,
		ParsedMessages: []protocol.ParsedMessage{message},
	}

}

func (parser *RocketMQStreamParser) parseHeader(headerBody []byte, serializedType byte) (*RocketMQMessage, error) {
	message := NewRocketMQMessage()
	switch serializedType {
	case serializationTypeJSON:
		var temp struct {
			RequestCode int16             `json:"code"`
			Language    string            `json:"language"`
			VersionFlag int16             `json:"version"`
			Opaque      int32             `json:"opaque"`
			RequestFlag int32             `json:"flag"`
			Remark      string            `json:"remark,omitempty"`
			Properties  map[string]string `json:"extFields,omitempty"`
		}

		if err := json.Unmarshal(headerBody, &temp); err != nil {
			return nil, fmt.Errorf("failed to parse JSON header: %w", err)
		}

		message.RequestCode = temp.RequestCode
		lFlag, _ := ConvertToLanguageCode(temp.Language)
		message.LanguageCode = lFlag
		message.VersionFlag = temp.VersionFlag
		message.Opaque = temp.Opaque
		message.RequestFlag = temp.RequestFlag
		message.RemarkLength = int32(len(temp.Remark))
		message.RemarkBuf = []byte(temp.Remark)
		message.PropertiesLen = int32(len(temp.Properties))
		message.Properties = temp.Properties

	case serializationTypeRocketMQ:
		if len(headerBody) < 18 {
			return nil, errors.New("invalid header size for private serialization")
		}

		message.RequestCode = int16(binary.BigEndian.Uint16(headerBody[requestCodeOffset : requestCodeOffset+2]))
		lCode, _ := convertToLanguageCodeFromByte(headerBody[languageCodeOffset])
		message.LanguageCode = lCode
		message.VersionFlag = int16(binary.BigEndian.Uint16(headerBody[versionFlagOffset : versionFlagOffset+2]))
		message.Opaque = int32(binary.BigEndian.Uint32(headerBody[opaqueOffset : opaqueOffset+4]))
		message.RequestFlag = int32(binary.BigEndian.Uint32(headerBody[requestFlagOffset : requestFlagOffset+4]))
		message.RemarkLength = int32(binary.BigEndian.Uint32(headerBody[remarkLengthOffset : remarkLengthOffset+4]))

		if int(message.RemarkLength) > len(headerBody[remarkLengthOffset+4:]) {
			return nil, errors.New("invalid remark length")
		}

		message.RemarkBuf = headerBody[remarkLengthOffset+4 : remarkLengthOffset+4+message.RemarkLength]

		propertiesStart := remarkLengthOffset + 4 + message.RemarkLength
		if len(headerBody[propertiesStart:]) < 4 {
			return nil, errors.New("invalid properties length")
		}

		message.PropertiesLen = int32(binary.BigEndian.Uint32(headerBody[propertiesStart : propertiesStart+4]))
		message.PropertiesBuf = headerBody[propertiesStart+4 : propertiesStart+4+message.PropertiesLen]

	default:
		return nil, fmt.Errorf("unsupported serialization type: %d", serializedType)
	}

	return message, nil
}

func (r *RocketMQStreamParser) FindBoundary(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType, startPos int) int {
	buffer := streamBuffer.Head().Buffer()
	common.ProtocolParserLog.Debugf("FindBoundary starting at position: %d, buffer length: %d", startPos, len(buffer))

	for i := startPos; i <= len(buffer)-16; i++ {
		frameSize := int(binary.BigEndian.Uint32(buffer[i : i+4]))
		if frameSize <= 0 {
			common.ProtocolParserLog.Debugf("Invalid frameSize=%d at position=%d", frameSize, i)
			continue
		}

		if i+frameSize+4 > len(buffer) {
			common.ProtocolParserLog.Debugf("Incomplete frame at position=%d, waiting for more data", i)
			return -1
		}

		headerLength := int(binary.BigEndian.Uint32(buffer[i+4 : i+8]))
		serializedType := byte((headerLength >> 24) & 0xFF)
		headerDataLen := headerLength & 0xFFFFFF

		if serializedType != 0x0 && serializedType != 0x1 {
			common.ProtocolParserLog.Debugf("Invalid serializedType=%d at position=%d", serializedType, i)
			continue
		}

		if headerDataLen <= 0 || headerDataLen != (frameSize-4) {
			common.ProtocolParserLog.Debugf("Invalid headerDataLen=%d at position=%d", headerDataLen, i)
			continue
		}

		if serializedType == serializationTypeJSON {
			if i+16 > len(buffer) {
				continue
			}
			if buffer[i+8] != '{' || buffer[i+9] != '"' || buffer[i+10] != 'c' || buffer[i+11] != 'o' ||
				buffer[i+12] != 'd' || buffer[i+13] != 'e' || buffer[i+14] != '"' || buffer[i+15] != ':' {
				common.ProtocolParserLog.Debugf("Invalid JSON format at position=%d", i)
				continue
			}
		}

		if serializedType == serializationTypeRocketMQ {
			if i+14 > len(buffer) {
				continue
			}
			requestCode := binary.BigEndian.Uint16(buffer[i+8 : i+10])
			lFlag := buffer[i+10]
			// vFlag := binary.BigEndian.Uint16(buffer[i+11 : i+13])

			if requestCode < 10 || lFlag >= byte(UNKNOWN_LANGUAGE) {
				common.ProtocolParserLog.Debugf("Invalid requestCode=%d or lFlag=%d at position=%d", requestCode, lFlag, i)
				continue
			}
		}

		if messageType == protocol.Response {
			if i+20 > len(buffer) {
				continue
			}
			opaque := int32(binary.BigEndian.Uint32(buffer[i+16 : i+20]))
			if _, exists := r.requestOpaqueMap[opaque]; !exists {
				common.ProtocolParserLog.Debugf("Opaque=%d not found in request map at position=%d", opaque, i)
				continue
			}
		}

		common.ProtocolParserLog.Debugf("Found boundary at position=%d with frameSize=%d", i, frameSize)
		return i
	}

	common.ProtocolParserLog.Debugln("No valid boundary found, returning -1.")
	return -1
}

func (r *RocketMQStreamParser) Match(reqStream *[]protocol.ParsedMessage, respStream *[]protocol.ParsedMessage) []protocol.Record {
	common.ProtocolParserLog.Debugf("Matching %d requests with %d responses.", len(*reqStream), len(*respStream))
	records := []protocol.Record{}

	reqMap := make(map[int32]*RocketMQMessage)
	for _, msg := range *reqStream {
		req := msg.(*RocketMQMessage)
		reqMap[req.Opaque] = req
	}

	// matching
	for _, msg := range *respStream {
		resp := msg.(*RocketMQMessage)
		if req, ok := reqMap[resp.Opaque]; ok {
			delete(r.requestOpaqueMap, req.Opaque)
			records = append(records, protocol.Record{
				Req:  req,
				Resp: resp,
			})
			delete(reqMap, req.Opaque)
		} else {
			common.ProtocolParserLog.Debugf("No matching request found for response Opaque=%d", resp.Opaque)
		}
	}

	// remove timeout requests
	currentTime := time.Now()
	for opaque, req := range reqMap {
		reqTime := time.Unix(0, int64(req.TimestampNs()))
		if currentTime.Sub(reqTime) > requestTimeoutDuration {
			common.ProtocolParserLog.Debugf("Removing request with Opaque=%d due to timeout", opaque)
			delete(reqMap, opaque)
		}
	}

	// remove matched requests
	newReqStream := []protocol.ParsedMessage{}
	for _, msg := range *reqStream {
		req := msg.(*RocketMQMessage)
		if _, exists := reqMap[req.Opaque]; exists {
			newReqStream = append(newReqStream, msg)
		}
	}
	*reqStream = newReqStream

	// clear all response
	*respStream = []protocol.ParsedMessage{}

	if len(reqMap) > 0 {
		common.ProtocolParserLog.Debugf("Unmatched requests remain: %d", len(reqMap))
	}

	return records
}
