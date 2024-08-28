package filter

import (
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"

	"github.com/jefurry/logrus"
)

var log *logrus.Logger = common.Log

var _ protocol.ProtocolFilter = NoopFilter{}

type NoopFilter struct {
}

func (n NoopFilter) FilterByProtocol(bpf.AgentTrafficProtocolT) bool {
	return true
}

func (n NoopFilter) FilterByRequest() bool {
	return false
}

func (n NoopFilter) FilterByResponse() bool {
	return false
}

func (NoopFilter) Filter(protocol.ParsedMessage, protocol.ParsedMessage) bool {
	return true
}

func IsNoopFilter(filter protocol.ProtocolFilter) bool {
	_, ok := filter.(NoopFilter)
	return ok
}
