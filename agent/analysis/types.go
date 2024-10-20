package analysis

import (
	anc "kyanos/agent/analysis/common"
	"kyanos/common"
)

type ConnStat struct {
	Count                 int
	FailedCount           int
	SamplesMap            map[anc.MetricType][]*anc.AnnotatedRecord
	PercentileCalculators map[anc.MetricType]*PercentileCalculator
	// AvgMap                map[MetricType]float32
	MaxMap map[anc.MetricType]float32
	SumMap map[anc.MetricType]float64
	Side   common.SideEnum

	ClassId             anc.ClassId
	HumanReadbleClassId string
	ClassfierType       anc.ClassfierType
	IsSub               bool
}

func (c *ConnStat) ClassIdAsHumanReadable(classId anc.ClassId) string {
	switch c.ClassfierType {
	case anc.None:
		return "All"
	case anc.Conn:
		return c.HumanReadbleClassId
	case anc.RemotePort:
		fallthrough
	case anc.LocalPort:
		fallthrough
	case anc.RemoteIp:
		return c.HumanReadbleClassId
	case anc.Protocol:
		return c.HumanReadbleClassId
	default:
		if c.HumanReadbleClassId != "" {
			return c.HumanReadbleClassId
		}
		return string(classId)
	}
}

func (c *ConnStat) GetValueByMetricType(l anc.LatencyMetric, m anc.MetricType) float64 {
	if l == anc.Avg {
		sum, ok := c.SumMap[m]
		if !ok {
			return 0
		}

		return sum / float64(c.Count)
	} else if l == anc.Max {
		max, ok := c.MaxMap[m]
		if !ok {
			return 0
		}
		return float64(max)
	} else if l == anc.P50 || l == anc.P90 || l == anc.P99 {
		var percent float32
		if l == anc.P50 {
			percent = 0.5
		} else if l == anc.P90 {
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
