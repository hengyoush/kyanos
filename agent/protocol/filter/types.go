package filter

import (
	"eapm-ebpf/bpf"
	"eapm-ebpf/common"

	"github.com/jefurry/logrus"
)

var log *logrus.Logger = common.Log

type ParsedMessage any
type MessageFilter interface {
	Filter(req ParsedMessage, resp ParsedMessage) bool
	FilterByProtocol(bpf.AgentTrafficProtocolT) bool
	FilterByRequest() bool
	FilterByResponse() bool
}

var _ MessageFilter = NoopFilter{}

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

func (NoopFilter) Filter(ParsedMessage, ParsedMessage) bool {
	return true
}

func IsNoopFilter(filter MessageFilter) bool {
	_, ok := filter.(NoopFilter)
	return ok
}
