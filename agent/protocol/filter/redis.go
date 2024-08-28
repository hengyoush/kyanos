package filter

import (
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/parser"
	"kyanos/bpf"
	"slices"
)

type RedisFilter struct {
	TargetCommands []string
}

func (r RedisFilter) Filter(req protocol.ParsedMessage, resp protocol.ParsedMessage) bool {
	redisReq, ok := req.(*parser.RedisMessage)
	if !ok {
		log.Warnf("[RedisFilter] cast to RedisMessage failed: %v\n", req)
		return false
	}
	if len(r.TargetCommands) == 0 {
		return true
	}

	return slices.Index(r.TargetCommands, redisReq.Command()) != -1
}

func (r RedisFilter) FilterByProtocol(p bpf.AgentTrafficProtocolT) bool {
	return p == bpf.AgentTrafficProtocolTKProtocolRedis
}

func (r RedisFilter) FilterByRequest() bool {
	return len(r.TargetCommands) > 0
}

func (r RedisFilter) FilterByResponse() bool {
	return false
}

var _ protocol.ProtocolFilter = RedisFilter{}
