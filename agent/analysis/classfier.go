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
	classfierMap[anc.HttpPath] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		httpReq, ok := ar.Record.Request().(*protocol.ParsedHttpRequest)
		if !ok {
			return "_not_a_http_req_", nil
		} else {
			return anc.ClassId(httpReq.Path), nil
		}
	}
	classfierMap[anc.RedisCommand] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		redisReq, ok := ar.Record.Request().(*protocol.RedisMessage)
		if !ok {
			return "_not_a_redis_req_", nil
		} else {
			return anc.ClassId(redisReq.Command()), nil
		}
	}

	classfierMap[anc.ProtocolAdaptive] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		redisReq, ok := ar.Record.Request().(*protocol.RedisMessage)
		if !ok {
			return "_not_a_redis_req_", nil
		} else {
			return anc.ClassId(redisReq.Command()), nil
		}
	}

	classIdHumanReadableMap = make(map[anc.ClassfierType]ClassIdAsHumanReadable)
	classIdHumanReadableMap[anc.RemoteIp] = func(ar *anc.AnnotatedRecord) string {
		return ar.ConnDesc.RemoteAddr.String()
	}
	classIdHumanReadableMap[anc.RemotePort] = func(ar *anc.AnnotatedRecord) string {
		return fmt.Sprintf("%d", ar.ConnDesc.RemotePort)
	}
	classIdHumanReadableMap[anc.LocalPort] = func(ar *anc.AnnotatedRecord) string {
		return fmt.Sprintf("%d", ar.ConnDesc.LocalPort)
	}
	classIdHumanReadableMap[anc.Conn] = func(ar *anc.AnnotatedRecord) string {
		return ar.ConnDesc.SimpleString()
	}
	classIdHumanReadableMap[anc.HttpPath] = func(ar *anc.AnnotatedRecord) string {
		httpReq, ok := ar.Record.Request().(*protocol.ParsedHttpRequest)
		if !ok {
			return "_not_a_http_req_"
		} else {
			return httpReq.Path
		}
	}
	classIdHumanReadableMap[anc.RedisCommand] = func(ar *anc.AnnotatedRecord) string {
		redisReq, ok := ar.Record.Request().(*protocol.RedisMessage)
		if !ok {
			return "_not_a_redis_req_"
		} else {
			return redisReq.Command()
		}
	}

	classIdHumanReadableMap[anc.Protocol] = func(ar *anc.AnnotatedRecord) string {
		return bpf.ProtocolNamesMap[bpf.AgentTrafficProtocolT(ar.Protocol)]
	}
}

func getClassfier(classfierType anc.ClassfierType, options anc.AnalysisOptions) Classfier {
	if classfierType == anc.ProtocolAdaptive {
		return func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
			c, ok := options.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolT(ar.Protocol)]
			if !ok {
				return classfierMap[anc.RemoteIp](ar)
			} else {
				return classfierMap[c](ar)
			}
		}
	} else {
		return classfierMap[classfierType]
	}
}

func GetClassfierType(classfierType anc.ClassfierType, options anc.AnalysisOptions, r *anc.AnnotatedRecord) anc.ClassfierType {
	if classfierType == anc.ProtocolAdaptive {
		c, ok := options.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolT(r.Protocol)]
		if ok {
			return c
		} else {
			return anc.RemoteIp
		}
	} else {
		return classfierType
	}
}

func getClassIdHumanReadableFunc(classfierType anc.ClassfierType, options anc.AnalysisOptions) (ClassIdAsHumanReadable, bool) {
	if classfierType == anc.ProtocolAdaptive {
		return func(ar *anc.AnnotatedRecord) string {
			c, ok := options.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolT(ar.Protocol)]
			if !ok {
				return classIdHumanReadableMap[anc.RemoteIp](ar)
			} else {
				return classIdHumanReadableMap[c](ar)
			}
		}, true
	} else {
		f, ok := classIdHumanReadableMap[classfierType]
		return f, ok
	}
}
