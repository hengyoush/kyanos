package rocketmq

import (
	"kyanos/agent/protocol"
)

var _ protocol.ParsedMessage = &RocketMQMessage{}

type RocketMQMessage struct {
	protocol.FrameBase
	RequestCode   int16
	LanguageCode  LanguageCode
	VersionFlag   int16
	Opaque        int32
	RequestFlag   int32
	RemarkLength  int32
	RemarkBuf     []byte
	PropertiesLen int32
	PropertiesBuf []byte
	Properties    map[string]string
	BodyBuf       []byte
	isReq         bool
}

var _ protocol.ProtocolStreamParser = &RocketMQStreamParser{}

type RocketMQStreamParser struct {
	requestOpaqueMap map[int32]struct{}
}
