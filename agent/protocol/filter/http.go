package filter

import (
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/parser"
	"kyanos/bpf"
	"slices"
)

var _ protocol.ProtocolFilter = HttpFilter{}

type HttpFilter struct {
	TargetPath     string
	TargetHostName string
	TargetMethods  []string
}

func (filter HttpFilter) FilterByProtocol(protocol bpf.AgentTrafficProtocolT) bool {
	return protocol == bpf.AgentTrafficProtocolTKProtocolHTTP
}

func (filter HttpFilter) FilterByRequest() bool {
	return filter.TargetPath != "" || len(filter.TargetMethods) > 0 || filter.TargetHostName != ""
}

func (filter HttpFilter) FilterByResponse() bool {
	return false
}

func (filter HttpFilter) Filter(parsedReq protocol.ParsedMessage, parsedResp protocol.ParsedMessage) bool {
	req, ok := parsedReq.(*parser.ParsedHttpRequest)
	if !ok {
		log.Warnf("[HttpFilter] cast to http.Request failed: %v\n", req)
		return false
	}

	if filter.TargetPath != "" && filter.TargetPath != req.Path {
		return false
	}
	if len(filter.TargetMethods) > 0 && !slices.Contains(filter.TargetMethods, req.Method) {
		return false
	}
	if filter.TargetHostName != "" && filter.TargetHostName != req.Host {
		return false
	}
	return true
}
