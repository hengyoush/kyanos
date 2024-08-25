package parser

import (
	"eapm-ebpf/agent/protocol"
	"eapm-ebpf/bpf"
	"eapm-ebpf/common"

	"github.com/jefurry/logrus"
)

var log *logrus.Logger = common.Log

type ParsedMessage any

type ProtocolParser interface {
	Parse(*protocol.BaseProtocolMessage) (any, error)
}

func GetParserByProtocol(protocol bpf.AgentTrafficProtocolT) ProtocolParser {
	switch protocol {
	case bpf.AgentTrafficProtocolTKProtocolHTTP:
		return HttpParser{}
	default:
		return nil
	}
}
