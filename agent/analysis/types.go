package analysis

import (
	"kyanos/common"

	"golang.org/x/exp/constraints"
)

type MetricType int

type MetricValueType interface {
	constraints.Integer | constraints.Float
}

type MetricTypeSet map[MetricType]bool

func NewMetricTypeSet(metricTypes []MetricType) MetricTypeSet {
	result := make(map[MetricType]bool)
	for _, t := range metricTypes {
		result[t] = true
	}
	return result
}

type MetricExtract[T MetricValueType] func(*AnnotatedRecord) T

const (
	ResponseSize MetricType = iota
	RequestSize
	TotalDuration
	BlackBoxDuration
	ReadFromSocketBufferDuration
)

func GetMetricExtractFunc[T MetricValueType](t MetricType) MetricExtract[T] {
	switch t {
	case ResponseSize:
		return func(ar *AnnotatedRecord) T {
			return T(ar.respSize)
		}
	case RequestSize:
		return func(ar *AnnotatedRecord) T { return T(ar.reqSize) }
	case TotalDuration:
		return func(ar *AnnotatedRecord) T { return T(ar.GetTotalDurationMills()) }
	case BlackBoxDuration:
		return func(ar *AnnotatedRecord) T { return T(ar.GetBlackBoxDurationMills()) }
	case ReadFromSocketBufferDuration:
		return func(ar *AnnotatedRecord) T { return T(ar.GetReadFromSocketBufferDurationMills()) }
	default:
		return func(ar *AnnotatedRecord) T { return T(ar.GetTotalDurationMills()) }
	}
}

type ConnStat struct {
	Count                 int
	FailedCount           int
	SamplesMap            map[MetricType][]*AnnotatedRecord
	PercentileCalculators map[MetricType]*PercentileCalculator
	// AvgMap                map[MetricType]float32
	MaxMap map[MetricType]float32
	SumMap map[MetricType]float64
	Side   common.SideEnum

	ClassId             ClassId
	HumanReadbleClassId string
	ClassfierType       ClassfierType
}

func (c *ConnStat) ClassIdAsHumanReadable(classId ClassId) string {
	switch c.ClassfierType {
	case None:
		return "All"
	case Conn:
		return c.HumanReadbleClassId
	case RemotePort:
		fallthrough
	case LocalPort:
		fallthrough
	case RemoteIp:
		return string(classId)
	case Protocol:
		return c.HumanReadbleClassId
	default:
		return string(classId)
	}
}
