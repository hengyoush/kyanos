package rocketmq

import (
	"encoding/binary"
	"errors"
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
)

func init() {

}

func (r *RocketMQMessage) FormatToString() string {
	return fmt.Sprintf("base=[%s] command=[%s] payload=[%s]", r.FrameBase.String(), "todo", r.Body)
}

func (r *RocketMQMessage) FormatToSummaryString() string {
	return "rocketmq"
}

func (r *RocketMQMessage) TimestampNs() uint64 {
	return 0
}

func (r *RocketMQMessage) ByteSize() int {
	return 0
}

func (r *RocketMQMessage) IsReq() bool {
	return r.isReq
}

func (r *RocketMQMessage) Seq() uint64 {
	return 0
}

func (r *RocketMQStreamParser) ParseStream(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType) protocol.ParseResult {
	head := streamBuffer.Head()
	buffer := head.Buffer()
	if len(buffer) < 8 {
		return protocol.ParseResult{
			ParseState: protocol.NeedsMoreData,
		}
	}

	frameSize := int(binary.BigEndian.Uint32(buffer[:4]))
	if frameSize > len(buffer) {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	headerLength := binary.BigEndian.Uint32(buffer[4:8])
	headerDataLen := headerLength & 0xFFFFFF
	serializedType := byte((headerLength >> 24) & 0xFF)

	if len(buffer) < 8+int(headerDataLen) {
		return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
	}

	headerBody := buffer[8 : 8+headerDataLen]
	body := buffer[8+headerDataLen : frameSize]
	message, err := r.parseHeader(headerBody, serializedType)
	if err != nil {
		return protocol.ParseResult{ParseState: protocol.Invalid, ReadBytes: int(frameSize)}
	}

	message.Body = body
	message.isReq = messageType == protocol.Request
	fb, ok := protocol.CreateFrameBase(streamBuffer, frameSize)

	if !ok {
		return protocol.ParseResult{
			ParseState: protocol.Ignore,
			ReadBytes:  frameSize,
		}
	} else {
		message.FrameBase = fb
		return protocol.ParseResult{
			ParseState:     protocol.Success,
			ReadBytes:      frameSize,
			ParsedMessages: []protocol.ParsedMessage{message},
		}
	}
}

func (parser *RocketMQStreamParser) parseHeader(headerBody []byte, serializedType byte) (*RocketMQMessage, error) {
	fmt.Println(serializedType)
	message := &RocketMQMessage{}
	if serializedType == 0 {
		if len(headerBody) < 18 {
			return nil, errors.New("invalid header size")
		}

		message.RequestCode = int16(binary.BigEndian.Uint16(headerBody[:2]))
		message.LanguageFlag = headerBody[2]
		message.VersionFlag = int16(binary.BigEndian.Uint16(headerBody[3:5]))
		message.Opaque = int32(binary.BigEndian.Uint32(headerBody[5:9]))
		message.RequestFlag = int32(binary.BigEndian.Uint32(headerBody[9:13]))
		message.RemarkLength = int32(binary.BigEndian.Uint32(headerBody[13:17]))

		if int(message.RemarkLength) > len(headerBody[17:]) {
			return nil, errors.New("invalid remark length")
		}
		message.Remark = headerBody[17 : 17+message.RemarkLength]
		propertiesStart := 17 + message.RemarkLength
		if len(headerBody[propertiesStart:]) < 4 {
			return nil, errors.New("invalid properties length")
		}
		message.PropertiesLen = int32(binary.BigEndian.Uint32(headerBody[propertiesStart:]))
		message.Properties = headerBody[propertiesStart+4 : propertiesStart+4+message.PropertiesLen]
	} else {
		return nil, errors.New("unsupported serialization type")
	}
	return message, nil
}

func (r *RocketMQStreamParser) FindBoundary(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType, startPos int) int {
	buffer := streamBuffer.Head().Buffer()[startPos:]
	for i := range buffer {
		if len(buffer[i:]) < 8 {
			return -1
		}
		frameSize := binary.BigEndian.Uint32(buffer[i : i+4])
		if int(frameSize) <= len(buffer[i:]) {
			return startPos + i
		}
	}
	return -1
}

func (r *RocketMQStreamParser) Match(reqStream *[]protocol.ParsedMessage, respStream *[]protocol.ParsedMessage) []protocol.Record {
	records := []protocol.Record{}
	for i := 0; i < len(*reqStream); i++ {
		req := (*reqStream)[i].(*RocketMQMessage)
		for j := 0; j < len(*respStream); j++ {
			resp := (*respStream)[j].(*RocketMQMessage)
			if req.Opaque == resp.Opaque {
				records = append(records, protocol.Record{
					Req:  req,
					Resp: resp,
				})
				*reqStream = (*reqStream)[1:]
				*respStream = (*respStream)[1:]
				break
			} else {
				continue
			}
		}
	}
	return records
}
