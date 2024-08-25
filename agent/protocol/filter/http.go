package filter

import (
	"kyanos/bpf"
	"net/http"
	"net/url"
	"slices"
)

var _ MessageFilter = HttpFilter{}

type HttpFilter struct {
	TargetPath    string
	TargetMethods []string
}

func (filter HttpFilter) FilterByProtocol(protocol bpf.AgentTrafficProtocolT) bool {
	return protocol == bpf.AgentTrafficProtocolTKProtocolHTTP
}

func (filter HttpFilter) FilterByRequest() bool {
	return filter.TargetPath != "" || len(filter.TargetMethods) > 0
}

func (filter HttpFilter) FilterByResponse() bool {
	return false
}

func (filter HttpFilter) Filter(parsedReq ParsedMessage, parsedResp ParsedMessage) bool {
	req, ok := parsedReq.(*http.Request)
	if !ok {
		log.Warnf("[HttpFilter] cast to http.Request failed: %v\n", req)
		return false
	}
	uri, err := url.ParseRequestURI(req.RequestURI)
	if err != nil {
		log.Errorln("[HttpFilter] parse uri failed:", err)
		return false
	}

	if filter.TargetPath != "" && filter.TargetPath != uri.Path {
		return false
	}
	if len(filter.TargetMethods) > 0 && !slices.Contains(filter.TargetMethods, req.Method) {
		return false
	}
	return true
}
