package analysis

import (
	"fmt"

	anc "kyanos/agent/analysis/common"
	"kyanos/agent/protocol"
	"kyanos/bpf"
)

type Classfier func(*anc.AnnotatedRecord) (anc.ClassId, error)
type ClassIdAsHumanReadable func(*anc.AnnotatedRecord) string

var classfierMap map[anc.ClassfierType]Classfier
var classIdHumanReadableMap map[anc.ClassfierType]ClassIdAsHumanReadable

func init() {
	classfierMap = make(map[anc.ClassfierType]Classfier)
	classfierMap[anc.None] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) { return "none", nil }
	classfierMap[anc.Conn] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		return anc.ClassId(ar.ConnDesc.Identity()), nil
	}
	classfierMap[anc.RemotePort] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		return anc.ClassId(fmt.Sprintf("%d", ar.RemotePort)), nil
	}
	classfierMap[anc.LocalPort] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		return anc.ClassId(fmt.Sprintf("%d", ar.LocalPort)), nil
	}
	classfierMap[anc.RemoteIp] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) { return anc.ClassId(ar.RemoteAddr.String()), nil }
	classfierMap[anc.Protocol] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		return anc.ClassId(fmt.Sprintf("%d", ar.Protocol)), nil
	}

	classIdHumanReadableMap = make(map[anc.ClassfierType]ClassIdAsHumanReadable)
	classIdHumanReadableMap[anc.Conn] = func(ar *anc.AnnotatedRecord) string {
		return ar.ConnDesc.SimpleString()
	}
	classIdHumanReadableMap[anc.HttpPath] = func(ar *anc.AnnotatedRecord) string {
		httpReq, ok := ar.Record.Request().(*protocol.ParsedHttpRequest)
		if !ok {
			return "__not_a_http_req__"
		} else {
			return httpReq.Path
		}
	}

	classIdHumanReadableMap[anc.Protocol] = func(ar *anc.AnnotatedRecord) string {
		return bpf.ProtocolNamesMap[bpf.AgentTrafficProtocolT(ar.Protocol)]
	}
}

func getClassfier(classfierType anc.ClassfierType) Classfier {
	return classfierMap[classfierType]
}
