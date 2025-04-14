package rocketmq

import (
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"
	"slices"
)

type Filter struct {
	TargetRequestCodes  []int32
	TargetLanguageCodes []LanguageCode
}

func (m Filter) Filter(req protocol.ParsedMessage, resp protocol.ParsedMessage) bool {
	rocketMQReq, ok := req.(*RocketMQMessage)
	if !ok {
		common.ProtocolParserLog.Warnf("[RocketMQFilter] cast to RocketMQMessage failed: %v\n", req)
		return false
	}

	pass := true

	pass = pass && (len(m.TargetRequestCodes) == 0 || slices.Index(m.TargetRequestCodes, int32(rocketMQReq.RequestCode)) != -1)
	pass = pass && (len(m.TargetLanguageCodes) == 0 || slices.Index(m.TargetLanguageCodes, rocketMQReq.LanguageCode) != -1)

	return pass
}

func (m Filter) FilterByProtocol(p bpf.AgentTrafficProtocolT) bool {
	return p == bpf.AgentTrafficProtocolTKProtocolRocketMQ
}

func (m Filter) FilterByRequest() bool {
	return len(m.TargetRequestCodes) > 0 || len(m.TargetLanguageCodes) > 0
}

func (m Filter) FilterByResponse() bool {
	return len(m.TargetRequestCodes) > 0 || len(m.TargetLanguageCodes) > 0
}

func (Filter) Protocol() bpf.AgentTrafficProtocolT {
	return bpf.AgentTrafficProtocolTKProtocolRocketMQ
}

var _ protocol.ProtocolFilter = Filter{}
