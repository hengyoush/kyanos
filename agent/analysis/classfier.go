package analysis

import "fmt"

type ClassfierType int

type Classfier func(*AnnotatedRecord) (ClassId, error)

var ClassfierTypeNames = map[ClassfierType]string{
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
	None ClassfierType = iota
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

var classfierMap map[ClassfierType]Classfier

func init() {
	classfierMap = make(map[ClassfierType]Classfier)
	classfierMap[None] = func(ar *AnnotatedRecord) (ClassId, error) { return "none", nil }
	classfierMap[Conn] = func(ar *AnnotatedRecord) (ClassId, error) {
		return ClassId(ar.ConnDesc.Identity()), nil
	}
	classfierMap[RemotePort] = func(ar *AnnotatedRecord) (ClassId, error) { return ClassId(fmt.Sprintf("%d", ar.RemotePort)), nil }
	classfierMap[LocalPort] = func(ar *AnnotatedRecord) (ClassId, error) { return ClassId(fmt.Sprintf("%d", ar.LocalPort)), nil }
	classfierMap[RemoteIp] = func(ar *AnnotatedRecord) (ClassId, error) { return ClassId(ar.RemoteAddr.String()), nil }
	classfierMap[Protocol] = func(ar *AnnotatedRecord) (ClassId, error) { return ClassId(fmt.Sprintf("%d", ar.Protocol)), nil }
}

func getClassfier(classfierType ClassfierType) Classfier {
	return classfierMap[classfierType]
}
