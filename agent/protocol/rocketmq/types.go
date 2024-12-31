package rocketmq

import (
	"kyanos/agent/protocol"
)

var _ protocol.ParsedMessage = &RocketMQMessage{}

type RocketMQMessage struct {
	protocol.FrameBase
	RequestCode   int16
	LanguageFlag  byte
	VersionFlag   int16
	Opaque        int32
	RequestFlag   int32
	RemarkLength  int32
	Remark        []byte
	PropertiesLen int32
	Properties    []byte
	Body          []byte
	isReq         bool
}

var _ protocol.ProtocolStreamParser = &RocketMQStreamParser{}

type RocketMQStreamParser struct {
}
