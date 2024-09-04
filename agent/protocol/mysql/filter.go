package mysql

import (
	"kyanos/agent/protocol"
	"kyanos/bpf"
)

type MysqlFilter struct {
}

func (m MysqlFilter) Filter(req protocol.ParsedMessage, resp protocol.ParsedMessage) bool {
	return true
}

func (m MysqlFilter) FilterByProtocol(p bpf.AgentTrafficProtocolT) bool {
	return p == bpf.AgentTrafficProtocolTKProtocolMySQL
}

func (m MysqlFilter) FilterByRequest() bool {
	return false
}

func (m MysqlFilter) FilterByResponse() bool {
	return false
}

var _ protocol.ProtocolFilter = MysqlFilter{}
