package stat

import "kyanos/common"

type ConnStatistics struct {
	common.ConnDesc
	Avg                 float32
	P99                 float32
	P999                float32
	Max                 float32
	BigResponseSamples  []*AnnotatedRecord
	SlowResponseSamples []*AnnotatedRecord
	RecentSamples       []*AnnotatedRecord
}
