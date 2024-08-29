package parser

import (
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"

	"github.com/jefurry/logrus"
)

var log *logrus.Logger = common.Log

func init() {
	protocol.ParsersMap[bpf.AgentTrafficProtocolTKProtocolHTTP] = HttpParser{}
	protocol.ParsersMap[bpf.AgentTrafficProtocolTKProtocolRedis] = RedisParser{}
}
