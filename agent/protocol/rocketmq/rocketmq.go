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
)

func init() {
	protocol.ParsersMap[bpf.AgentTrafficProtocolTKProtocolRocketMQ] = func() protocol.ProtocolStreamParser {
		return &RocketMQStreamParser{}
	}
}

func NewRocketMQMessage() *RocketMQMessage {
	return &RocketMQMessage{
		LanguageCode:  UNKNOWN,
		RemarkBuf:     make([]byte, 0),
		PropertiesBuf: make([]byte, 0),
		BodyBuf:       make([]byte, 0),
		Properties:    map[string]string{},
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
		common.ProtocolParserLog.Warn("Buffer too small for header, needs more data.")
		return protocol.ParseResult{
			ParseState: protocol.NeedsMoreData,
		}
	}

	frameSize := int(binary.BigEndian.Uint32(buffer[:4]))
	if frameSize <= 0 {
		common.ProtocolParserLog.Warnf("Invalid frame size: %d", frameSize)
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
		common.ProtocolParserLog.Warnf("Incomplete header detected: headerDataLen=%d, frameSize=%d.", headerDataLen, frameSize)
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
		common.ProtocolParserLog.Warnf("Failed to create FrameBase for frameSize=%d", frameSize)
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
	case 0: // json
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
		lFlag, _ := convertToLanguageCode(temp.Language)
		message.LanguageCode = lFlag
		message.VersionFlag = temp.VersionFlag
		message.Opaque = temp.Opaque
		message.RequestFlag = temp.RequestFlag
		message.RemarkLength = int32(len(temp.Remark))
		message.RemarkBuf = []byte(temp.Remark)
		message.PropertiesLen = int32(len(temp.Properties))
		message.Properties = temp.Properties

	case 1: // ROCKETMQ
		if len(headerBody) < 18 {
			return nil, errors.New("invalid header size for private serialization")
		}

		message.RequestCode = int16(binary.BigEndian.Uint16(headerBody[:2]))
		lCode, _ := convertToLanguageCodeFromByte(headerBody[2])
		message.LanguageCode = lCode
		message.VersionFlag = int16(binary.BigEndian.Uint16(headerBody[3:5]))
		message.Opaque = int32(binary.BigEndian.Uint32(headerBody[5:9]))
		message.RequestFlag = int32(binary.BigEndian.Uint32(headerBody[9:13]))
		message.RemarkLength = int32(binary.BigEndian.Uint32(headerBody[13:17]))

		if int(message.RemarkLength) > len(headerBody[17:]) {
			return nil, errors.New("invalid remark length")
		}

		message.RemarkBuf = headerBody[17 : 17+message.RemarkLength]

		propertiesStart := 17 + message.RemarkLength
		if len(headerBody[propertiesStart:]) < 4 {
			return nil, errors.New("invalid properties length")
		}

		message.PropertiesLen = int32(binary.BigEndian.Uint32(headerBody[propertiesStart:]))
		message.PropertiesBuf = headerBody[propertiesStart+4 : propertiesStart+4+message.PropertiesLen]

	default:
		return nil, fmt.Errorf("unsupported serialization type: %d", serializedType)
	}

	return message, nil
}

func (r *RocketMQStreamParser) FindBoundary(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType, startPos int) int {
	buffer := streamBuffer.Head().Buffer()
	common.ProtocolParserLog.Debugf("FindBoundary starting at position: %d, buffer length: %d", startPos, len(buffer))

	for i := startPos; i <= len(buffer)-8; i++ {
		frameSize := int(binary.BigEndian.Uint32(buffer[i : i+4]))

		if frameSize <= 0 || frameSize > len(buffer)-i {
			common.ProtocolParserLog.Warnf("Skipping invalid frameSize=%d at position=%d", frameSize, i)
			continue
		}

		if i+frameSize <= len(buffer) {
			common.ProtocolParserLog.Debugf("Found boundary at position=%d with frameSize=%d", i, frameSize)
			return i
		}
	}

	common.ProtocolParserLog.Warn("No valid boundary found, returning -1.")
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

	for _, msg := range *respStream {
		resp := msg.(*RocketMQMessage)
		if req, ok := reqMap[resp.Opaque]; ok {
			records = append(records, protocol.Record{
				Req:  req,
				Resp: resp,
			})
			delete(reqMap, resp.Opaque)
		} else {
			common.ProtocolParserLog.Warnf("No matching request found for response Opaque=%d", resp.Opaque)
		}
	}

	if len(reqMap) > 0 {
		common.ProtocolParserLog.Warnf("Unmatched requests remain: %d", len(reqMap))
	}

	return records
}
