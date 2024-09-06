package stat

import "fmt"

type ClassfierType int

type Classfier func(*AnnotatedRecord) (classId, error)

const (
	None ClassfierType = iota
	RemotePort
	LocalPort
	RemoteIp
	Protocol

	// Http
	HttpPath

	// Redis
	RedisCommand
)

type classId string

var classfierMap map[ClassfierType]Classfier

func init() {
	classfierMap[None] = func(ar *AnnotatedRecord) (classId, error) { return "none", nil }
	classfierMap[RemotePort] = func(ar *AnnotatedRecord) (classId, error) { return classId(fmt.Sprintf("%d", ar.RemotePort)), nil }
	classfierMap[LocalPort] = func(ar *AnnotatedRecord) (classId, error) { return classId(fmt.Sprintf("%d", ar.LocalPort)), nil }
	classfierMap[Protocol] = func(ar *AnnotatedRecord) (classId, error) { return classId(fmt.Sprintf("%d", ar.Protocol)), nil }
}

func getClassfier(classfierType ClassfierType) Classfier {
	return classfierMap[classfierType]
}
