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

func (m MetricTypeSet) AllEnabledMetrciType() []MetricType {
	var result []MetricType
	for metricType, enabled := range m {
		if enabled {
			result = append(result, metricType)
		}
	}
	return result
}

func (m MetricTypeSet) GetFirstEnabledMetricType() MetricType {
	for metricType, enabled := range m {
		if enabled {
			return metricType
		}
	}
	return NoneType
}

type MetricExtract[T MetricValueType] func(*AnnotatedRecord) T

const (
	ResponseSize MetricType = iota
	RequestSize
	TotalDuration
	BlackBoxDuration
	ReadFromSocketBufferDuration
	NoneType
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

func (c *ConnStat) GetValueByMetricType(l LatencyMetric, m MetricType) float64 {
	if l == Avg {
		sum, ok := c.SumMap[m]
		if !ok {
			return 0
		}

		return sum / float64(c.Count)
	} else if l == Max {
		max, ok := c.MaxMap[m]
		if !ok {
			return 0
		}
		return float64(max)
	} else if l == P50 || l == P90 || l == P99 {
		var percent float32
		if l == P50 {
			percent = 0.5
		} else if l == P90 {
			percent = 0.90
		} else {
			percent = 0.99
		}
		p, ok := c.PercentileCalculators[m]
		if !ok {
			return 0
		}
		return p.CalculatePercentile(float64(percent))
	} else {
		panic("Not implemneted!")
	}
}

type LatencyMetric int

const (
	Avg LatencyMetric = iota
	Max
	P50
	P90
	P99
)
