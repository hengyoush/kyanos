package protocol

import "kyanos/bpf"

type LatencyFilter struct {
	MinLatency float64
}

func (filter LatencyFilter) Filter(latency float64) bool {
	if filter.MinLatency <= 0 {
		return true
	}
	return latency >= filter.MinLatency
}

type SizeFilter struct {
	MinReqSize  int64
	MinRespSize int64
}

func (filter SizeFilter) FilterByReqSize(reqSize int64) bool {
	if filter.MinReqSize <= 0 {
		return true
	}
	return reqSize >= filter.MinReqSize
}

func (filter SizeFilter) FilterByRespSize(respSize int64) bool {
	if filter.MinRespSize <= 0 {
		return true
	}
	return respSize >= filter.MinRespSize
}

var _ ProtocolFilter = NoopFilter{}

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

var _ ProtocolFilter = BaseFilter{}

type BaseFilter struct {
}

func (n BaseFilter) FilterByProtocol(p bpf.AgentTrafficProtocolT) bool {
	return p != bpf.AgentTrafficProtocolTKProtocolUnknown
}

func (n BaseFilter) FilterByRequest() bool {
	return false
}

func (n BaseFilter) FilterByResponse() bool {
	return false
}

func (BaseFilter) Filter(ParsedMessage, ParsedMessage) bool {
	return true
}

func IsNoopFilter(filter ProtocolFilter) bool {
	_, ok := filter.(NoopFilter)
	return ok
}
