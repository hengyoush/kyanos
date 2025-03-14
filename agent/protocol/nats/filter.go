package nats

import (
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"
	"slices"
)

var _ protocol.ProtocolFilter = NatsFilter{}

type NatsFilter struct {
	Protocols []string
	Subjects  []string
}

func (filter NatsFilter) FilterByProtocol(protocol bpf.AgentTrafficProtocolT) bool {
	return protocol == bpf.AgentTrafficProtocolTKProtocolNATS
}

func (filter NatsFilter) FilterByRequest() bool {
	return len(filter.Protocols) > 0 || len(filter.Subjects) > 0
}

func (filter NatsFilter) FilterByResponse() bool {
	return false
}

func (filter NatsFilter) Filter(req protocol.ParsedMessage, rsp protocol.ParsedMessage) bool {
	natsReq, ok := req.(*NatsMessage)
	if !ok {
		common.ProtocolParserLog.Warnf("[NATSFilter] cast to NatsMessage failed: %v\n", req)
		return false
	}
	if len(filter.Protocols) > 0 && !slices.Contains(filter.Protocols, natsReq.ProtocolCode.String()) {
		return false
	}
	if len(filter.Subjects) > 0 && len(natsReq.Subject) > 0 && !slices.Contains(filter.Subjects, natsReq.Subject) {
		return false
	}
	return true
}
