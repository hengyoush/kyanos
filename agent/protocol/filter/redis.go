package filter

import (
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/parser"
	"kyanos/bpf"
	"slices"
	"strings"
)

type RedisFilter struct {
	TargetCommands []string
	TargetKeys     []string
	KeyPrefix      string
}

func extractKeyFromPayLoad(redisMessage *parser.RedisMessage) string {
	payload := redisMessage.Payload()
	spaceIdx := strings.Index(payload, " ")
	if spaceIdx == -1 {
		return payload
	} else {
		return payload[0:spaceIdx]
	}
}

func (r RedisFilter) Filter(req protocol.ParsedMessage, resp protocol.ParsedMessage) bool {
	redisReq, ok := req.(*parser.RedisMessage)
	if !ok {
		log.Warnf("[RedisFilter] cast to RedisMessage failed: %v\n", req)
		return false
	}
	pass := true
	pass = pass && (len(r.TargetCommands) == 0 || slices.Index(r.TargetCommands, redisReq.Command()) != -1)
	firstKey := extractKeyFromPayLoad(redisReq)
	pass = pass && (len(r.TargetKeys) == 0 || slices.Index(r.TargetKeys, firstKey) != -1)
	pass = pass && (r.KeyPrefix == "" || strings.HasPrefix(firstKey, r.KeyPrefix))

	return pass
}

func (r RedisFilter) FilterByProtocol(p bpf.AgentTrafficProtocolT) bool {
	return p == bpf.AgentTrafficProtocolTKProtocolRedis
}

func (r RedisFilter) FilterByRequest() bool {
	return len(r.TargetCommands) > 0 || len(r.TargetKeys) > 0 || r.KeyPrefix != ""
}

func (r RedisFilter) FilterByResponse() bool {
	return false
}

var _ protocol.ProtocolFilter = RedisFilter{}
