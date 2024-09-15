package render

import (
	"cmp"
	"fmt"
	"kyanos/agent/analysis"
	"kyanos/agent/protocol"
	"kyanos/common"
	"slices"
	"time"

	"github.com/jefurry/logrus"
)

var log *logrus.Logger = logrus.New()

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
	s += fmt.Sprintf("[---------------------------------------Kyanos Stat Report %s-----------------------------------------------]\n", time.Now().Local().Format("2006-01-02 15:04:05"))
	if len(r.EnabledMetricTypeSet.AllEnabledMetrciType()) == 1 {
		metricType := r.EnabledMetricTypeSet.GetFirstEnabledMetricType()
		slices.SortFunc(constats, func(c1, c2 *analysis.ConnStat) int {
			v1 := c1.GetValueByMetricType(r.SortBy, metricType)
			v2 := c2.GetValueByMetricType(r.SortBy, metricType)
			return cmp.Compare(v2, v1)
		})
	}
	if len(constats) > r.AnalysisOptions.DisplayLimit {
		constats = constats[:r.AnalysisOptions.DisplayLimit]
	}

	for _, stat := range constats {
		const HEADER_TEMPLATE = "%s: %s" // class type: class id

		s += fmt.Sprintf(HEADER_TEMPLATE, analysis.ClassfierTypeNames[stat.ClassfierType], stat.ClassIdAsHumanReadable(stat.ClassId))
		s += "\n"

		for metricType := range stat.SamplesMap {
			const METRIC_TEMPLATE = "[ %s ] avg: %.3f%s, max: %.3f%s, P50: %.3f%s, P90: %.3f%s, P99: %.3f%s (count: %d|failed: %d)\n"

			var avg float32
			if stat.Count != 0 {
				avg = float32(stat.SumMap[metricType] / float64(stat.Count))
			}
			max := stat.MaxMap[metricType]
			pCalc := stat.PercentileCalculators[metricType]
			p50, p90, p99 := pCalc.CalculatePercentile(0.5), pCalc.CalculatePercentile(0.9), pCalc.CalculatePercentile(0.99)
			unit := MetricTypeUnit[metricType]
			s += fmt.Sprintf(METRIC_TEMPLATE, metricName(metricType, r.Side), avg, unit, max, unit, p50, unit, p90, unit, p99, unit, stat.Count, stat.FailedCount)
		}
		s += "\n"

		for metricType, records := range stat.SamplesMap {
			if len(records) == 0 {
				continue
			}
			const SAMPLES_HEADER = "[ Top%d %s Samples ]\n"
			s += fmt.Sprintf(SAMPLES_HEADER, len(records), metricSampleName(metricType, r.Side))
			for i := range records {
				record := records[len(records)-i-1]
				s += fmt.Sprintf("----------------------------------------Top %s Sample %d---------------------------------------------\n", metricSampleName(metricType, r.Side), i+1)
				if r.FullRecordBody {
					s += record.String(analysis.AnnotatedRecordToStringOptions{
						MetricTypeSet: r.AnalysisOptions.EnabledMetricTypeSet,
						RecordToStringOptions: protocol.RecordToStringOptions{
							RecordMaxDumpBytes: 1024,
							IncludeReqBody:     true,
							IncludeRespBody:    true,
						},
						IncludeSyscallStat: false,
					})
				} else {
					s += record.String(analysis.AnnotatedRecordToStringOptions{
						MetricTypeSet: r.AnalysisOptions.EnabledMetricTypeSet,
						RecordToStringOptions: protocol.RecordToStringOptions{
							RecordMaxDumpBytes: 1024,
							IncludeReqSummary:  true,
							IncludeRespSummary: true,
						},
						IncludeSyscallStat: false,
					})
				}
			}
		}

		s += "--------------------------------------------------------------------------------------\n"
	}
	return s
}

func metricName(metricType analysis.MetricType, side common.SideEnum) string {

	metricName := MetricTypeNames[metricType]
	if metricType == analysis.BlackBoxDuration {
		if side == common.ClientSide {
			metricName = "Network Duration"
		} else {
			metricName = "Server Internal Duration"
		}
	}
	return metricName
}

func metricSampleName(metricType analysis.MetricType, side common.SideEnum) string {

	metricName := MetricTypeNames[metricType]
	if metricType == analysis.BlackBoxDuration {
		if side == common.ClientSide {
			metricName = "Max Network Duration"
		} else {
			metricName = "Max Server Internal Duration"
		}
	}
	return metricName
}
