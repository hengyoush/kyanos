package parser

import (
	"fmt"
	"kyanos/agent/protocol"
	"kyanos/common"
	"strconv"
)

const (
	kSimpleStringMarker = '+'
	kErrorMarker        = '-'
	kIntegerMarker      = ':'
	kBulkStringsMarker  = '$'
	kArrayMarker        = '*'
	kTerminalSequence   = "\r\n"
	kNullSize           = -1
)

var redisCommandsMap map[string][]string

type RedisParser struct {
}

type RedisMessage struct {
	protocol.FrameBase
	payload string
	command string
}

func (m *RedisMessage) Command() string {
	return m.command
}

func (m *RedisMessage) FormatToString() string {
	return fmt.Sprintf("base=[%s] payload=[%s]", m.FrameBase.String(), m.payload)
}

func ParseSize(decoder *protocol.BinaryDecoder) (int, error) {
	str, err := decoder.ExtractStringUntil(kTerminalSequence)
	if err != nil {
		return 0, err
	}
	const kSizeStrMaxLen = 16
	if len(str) > kSizeStrMaxLen {
		return 0, common.NewInvalidArgument(
			fmt.Sprintf("Redis size string is longer than %d, which indicates traffic is misclassified as Redis.", kSizeStrMaxLen))
	}
	// Length could be -1, which stands for NULL, and means the value is not set.
	// That's different than an empty string, which length is 0.
	// So here we initialize the value to -2.
	size := -2
	size, err = strconv.Atoi(str)
	if err != nil {
		return 0, common.NewInvalidArgument(fmt.Sprintf("String '%s' cannot be parsed as integer", str))
	}
	if size < kNullSize {
		return 0, common.NewInvalidArgument(fmt.Sprintf("Size cannot be less than %d, got '%s'", kNullSize, str))
	}
	return size, nil
}

func ParseBulkString(decoder *protocol.BinaryDecoder, msg *protocol.BaseProtocolMessage) (string, error) {
	const maxLen int = 512 * 1024 * 1024
	length, err := ParseSize(decoder)
	if err != nil {
		return "", err
	}
	if length > maxLen {
		return "", common.NewInvalidArgument(fmt.Sprintf("Length cannot be larger than 512MB, got '%d'", length))
	}
	if length == kNullSize {
		return "<NULL>", nil
	}
	str, err := decoder.ExtractString(length + len(kTerminalSequence))
	if err != nil {
		return "", err
	}
	return str, nil
}

func ParseArray(decoder *protocol.BinaryDecoder, msg *protocol.BaseProtocolMessage) (*RedisMessage, error) {
	size, err := ParseSize(decoder)
	if err != nil {
		return nil, err
	}
	if size == kNullSize {
		return &RedisMessage{
			FrameBase: protocol.NewFrameBase(msg.StartTs, int(msg.TotalBytes())),
			payload:   "[NULL]",
		}, nil
	}
	msgSlice := make([]*RedisMessage, 0)
	for i := 0; i < size; i++ {
		_msg, err := ParseMessage(decoder, msg)
		if err != nil {
			return nil, err
		}
		msgSlice = append(msgSlice, _msg)
	}

	ret := &RedisMessage{
		FrameBase: protocol.NewFrameBase(msg.StartTs, int(msg.TotalBytes())),
	}
	if len(msgSlice) >= 2 {
		candidateCmd := msgSlice[0].payload + " " + msgSlice[1].payload
		_, ok := redisCommandsMap[candidateCmd]
		if ok {
			msgSlice = msgSlice[2:]
			ret.command = candidateCmd
			for _, each := range msgSlice {
				ret.payload += each.payload
				ret.payload += " "
			}
		} else {
			for _, each := range msgSlice {
				ret.payload += each.payload
				ret.payload += " "
			}
		}
	}
	return ret, nil
}

func ParseMessage(decoder *protocol.BinaryDecoder, msg *protocol.BaseProtocolMessage) (*RedisMessage, error) {

	typeMarker, err := decoder.ExtractByte()
	if err != nil {
		return nil, err
	}

	switch typeMarker {
	case kSimpleStringMarker:
		str, err := decoder.ExtractStringUntil(kTerminalSequence)
		if err != nil {
			return nil, err
		}
		return &RedisMessage{
			FrameBase: protocol.NewFrameBase(msg.StartTs, int(msg.TotalBytes())),
			payload:   str,
		}, nil
	case kBulkStringsMarker:
		str, err := ParseBulkString(decoder, msg)
		if err != nil {
			return nil, err
		}
		return &RedisMessage{
			FrameBase: protocol.NewFrameBase(msg.StartTs, int(msg.TotalBytes())),
			payload:   str,
		}, nil
	case kErrorMarker:
		str, err := decoder.ExtractStringUntil(kTerminalSequence)
		if err != nil {
			return nil, err
		}
		return &RedisMessage{
			FrameBase: protocol.NewFrameBase(msg.StartTs, int(msg.TotalBytes())),
			payload:   "-" + str,
		}, nil
	case kIntegerMarker:
		str, err := decoder.ExtractStringUntil(kTerminalSequence)
		if err != nil {
			return nil, err
		}
		return &RedisMessage{
			FrameBase: protocol.NewFrameBase(msg.StartTs, int(msg.TotalBytes())),
			payload:   str,
		}, nil
	case kArrayMarker:
		return ParseArray(decoder, msg)
	default:
		return nil, common.NewInvalidArgument(fmt.Sprintf("Unexpected Redis type marker char (displayed as integer): %d", typeMarker))
	}
}

func (RedisParser) Parse(msg *protocol.BaseProtocolMessage) (protocol.ParsedMessage, error) {
	decoder := protocol.NewBinaryDecoder(msg.Data())
	return ParseMessage(decoder, msg)
}
