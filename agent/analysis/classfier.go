package analysis

import (
	"fmt"

	anc "kyanos/agent/analysis/common"
	"kyanos/agent/protocol"
	"kyanos/bpf"
)

type Classfier func(*anc.AnnotatedRecord) (ClassId, error)
type ClassIdAsHumanReadable func(*anc.AnnotatedRecord) string

var ClassfierTypeNames = map[anc.ClassfierType]string{
	None:         "none",
	Conn:         "conn",
	RemotePort:   "remote-port",
	LocalPort:    "local-port",
	RemoteIp:     "remote-ip",
	Protocol:     "protocol",
	HttpPath:     "http-path",
	RedisCommand: "redis-command",
}

const (
	None anc.ClassfierType = iota
	Conn
	RemotePort
	LocalPort
	RemoteIp
	Protocol

	// Http
	HttpPath

	// Redis
	RedisCommand
)

type ClassId string

var classfierMap map[anc.ClassfierType]Classfier
var classIdHumanReadableMap map[anc.ClassfierType]ClassIdAsHumanReadable

func init() {
	classfierMap = make(map[anc.ClassfierType]Classfier)
	classfierMap[None] = func(ar *anc.AnnotatedRecord) (ClassId, error) { return "none", nil }
	classfierMap[Conn] = func(ar *anc.AnnotatedRecord) (ClassId, error) {
		return ClassId(ar.ConnDesc.Identity()), nil
	}
	classfierMap[RemotePort] = func(ar *anc.AnnotatedRecord) (ClassId, error) { return ClassId(fmt.Sprintf("%d", ar.RemotePort)), nil }
	classfierMap[LocalPort] = func(ar *anc.AnnotatedRecord) (ClassId, error) { return ClassId(fmt.Sprintf("%d", ar.LocalPort)), nil }
	classfierMap[RemoteIp] = func(ar *anc.AnnotatedRecord) (ClassId, error) { return ClassId(ar.RemoteAddr.String()), nil }
	classfierMap[Protocol] = func(ar *anc.AnnotatedRecord) (ClassId, error) { return ClassId(fmt.Sprintf("%d", ar.Protocol)), nil }

	classIdHumanReadableMap = make(map[anc.ClassfierType]ClassIdAsHumanReadable)
	classIdHumanReadableMap[Conn] = func(ar *anc.AnnotatedRecord) string {
		return ar.ConnDesc.String()
	}
	classIdHumanReadableMap[HttpPath] = func(ar *anc.AnnotatedRecord) string {
		httpReq, ok := ar.Record.Request().(*protocol.ParsedHttpRequest)
		if !ok {
			return "__not_a_http_req__"
		} else {
			return httpReq.Path
		}
	}

	classIdHumanReadableMap[Protocol] = func(ar *anc.AnnotatedRecord) string {
		return bpf.ProtocolNamesMap[bpf.AgentTrafficProtocolT(ar.Protocol)]
	}
}

func getClassfier(classfierType anc.ClassfierType) Classfier {
	return classfierMap[classfierType]
}
