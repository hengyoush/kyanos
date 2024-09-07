package render

import (
	"fmt"
	"kyanos/agent/analysis"
	"kyanos/common"
)

var log = common.Log

type RenderOptions struct {
}

type Render struct {
	resultChannel <-chan []*analysis.ConnStat
	stopper       <-chan int
	*analysis.AnalysisOptions
}

func CreateRender(resultChannel <-chan []*analysis.ConnStat, stopper chan int, options *analysis.AnalysisOptions) *Render {
	return &Render{
		resultChannel:   resultChannel,
		stopper:         stopper,
		AnalysisOptions: options,
	}
}

func (r *Render) Run() {
	for {
		select {
		case <-r.stopper:
			continue
			// return
		case records := <-r.resultChannel:
			str := r.simpleRender(records)
			log.Infoln(str)
		}
	}
}

func (r *Render) simpleRender(constats []*analysis.ConnStat) string {

	var s string
	for idx, stat := range constats {
		if idx+1 > r.AnalysisOptions.DisplayLimit {
			break
		}
		const HEADER_TEMPLATE = "%s: %s" // class type: class id

		s += fmt.Sprintf(HEADER_TEMPLATE, analysis.ClassfierTypeNames[stat.ClassfierType], stat.ClassIdAsHumanReadable(stat.ClassId))
		s += "\n"

		for metricType := range stat.SamplesMap {
			const METRIC_TEMPLATE = "[ %s ] count: %d(failed: %d), avg: %.3f%s, max: %.3f%s, P50: %.3f%s, P90: %.3f%s, P99: %.3f%s\n"

			var avg float32
			if stat.Count != 0 {
				avg = float32(stat.SumMap[metricType] / float64(stat.Count))
			}
			max := stat.MaxMap[metricType]
			pCalc := stat.PercentileCalculators[metricType]
			p50, p90, p99 := pCalc.CalculatePercentile(0.5), pCalc.CalculatePercentile(0.9), pCalc.CalculatePercentile(0.99)
			unit := MetricTypeUnit[metricType]
			s += fmt.Sprintf(METRIC_TEMPLATE, MetricTypeNames[metricType], stat.Count, stat.FailedCount, avg, unit, max, unit, p50, unit, p90, unit, p99, unit)
		}
		s += "\n"

		for metricType, records := range stat.SamplesMap {
			if len(records) == 0 {
				continue
			}
			const SAMPLES_HEADER = "[ Top%d %s Samples ]\n"
			s += fmt.Sprintf(SAMPLES_HEADER, len(records), MetricTypeSampleNames[metricType])
			for i := range records {
				record := records[len(records)-i-1]
				s += record.String(analysis.AnnotatedRecordToStringOptions{})
			}
		}

		s += "--------------------------------------------------------------------------------------\n"
	}
	return s
}
