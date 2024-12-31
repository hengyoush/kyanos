package rocketmq

import (
	"kyanos/agent/protocol"
	"kyanos/bpf"
)

type Filter struct {
}

func (m Filter) Filter(req protocol.ParsedMessage, resp protocol.ParsedMessage) bool {
	return true
}

func (m Filter) FilterByProtocol(p bpf.AgentTrafficProtocolT) bool {
	return p == bpf.AgentTrafficProtocolTKProtocolRocketMQ
}

func (m Filter) FilterByRequest() bool {
	return false
}

func (m Filter) FilterByResponse() bool {
	return false
}

var _ protocol.ProtocolFilter = Filter{}
