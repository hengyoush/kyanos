package stat

import (
	"golang.org/x/exp/constraints"
)

type MetricType int

type MetricValueType interface {
	constraints.Integer | constraints.Float
}

type MetricTypeSet map[int]bool

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
		return func(ar *AnnotatedRecord) T { return T(ar.blackBoxDuration) }
	case ReadFromSocketBufferDuration:
		return func(ar *AnnotatedRecord) T { return T(ar.readFromSocketBufferDuration) }
	default:
		return func(ar *AnnotatedRecord) T { return T(ar.GetTotalDurationMills()) }
	}
}

type ConnStat struct {
	Count                 int
	FailedCount           int
	Avg                   float32
	Max                   float32
	samplesMap            map[MetricType][]*AnnotatedRecord
	percentileCalculators map[MetricType]*PercentileCalculator

	classId
	sum float64
}
