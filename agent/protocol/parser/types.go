package parser

import (
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"

	"github.com/jefurry/logrus"
)

var log *logrus.Logger = common.Log

func GetParserByProtocol(protocol bpf.AgentTrafficProtocolT) protocol.ProtocolParser {
	switch protocol {
	case bpf.AgentTrafficProtocolTKProtocolHTTP:
		return HttpParser{}
	case bpf.AgentTrafficProtocolTKProtocolRedis:
		return RedisParser{}
	default:
		return nil
	}
}
