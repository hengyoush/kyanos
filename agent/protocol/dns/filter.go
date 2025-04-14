package dns

import (
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"strings"
)

var _ protocol.ProtocolFilter = &DnsFilter{}

type DnsFilter struct {
	targetHost string
}

func NewDNSFilter(targetHost string) *DnsFilter {
	return &DnsFilter{
		targetHost: targetHost,
	}
}

func (d *DnsFilter) Filter(req protocol.ParsedMessage, resp protocol.ParsedMessage) bool {
	reqFrame := req.(*Frame)
	if d.targetHost == "" {
		return true
	}
	for _, record := range reqFrame.Records {
		if strings.HasPrefix(record.Name, d.targetHost) {
			return true
		}
	}
	return false
}

func (d *DnsFilter) FilterByProtocol(p bpf.AgentTrafficProtocolT) bool {
	return p == bpf.AgentTrafficProtocolTKProtocolDNS
}

func (d *DnsFilter) FilterByRequest() bool {
	return true
}

func (d *DnsFilter) FilterByResponse() bool {
	return false
}

func (DnsFilter) Protocol() bpf.AgentTrafficProtocolT {
	return bpf.AgentTrafficProtocolTKProtocolDNS
}
