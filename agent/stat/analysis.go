package stat

import (
	"cmp"
	"kyanos/agent/protocol"
	"kyanos/common"
	"math"
	"slices"
)

const MaxRecentRecordsNumber = 10
const MaxSlowResponseSamplesNumber = 10

type ShowOption struct {
	EnabledMetricTypeSet MetricTypeSet
	SampleLimit          int
	ClassfierType
}

type aggregator struct {
	*ShowOption
	*ConnStat
}

func createAggregator(classId classId, aggregateOption *ShowOption) aggregator {
	aggregator := aggregator{
		ShowOption: aggregateOption,
		ConnStat: &ConnStat{
			classId: classId,
		},
	}
	for metricType, enabled := range aggregateOption.EnabledMetricTypeSet {
		if enabled {
			aggregator.percentileCalculators[MetricType(metricType)] = &PercentileCalculator{}
			aggregator.samplesMap[MetricType(metricType)] = make([]*AnnotatedRecord, 0)
		}
	}
	return aggregator
}

func (a aggregator) receive(record *AnnotatedRecord) error {
	o := a.ConnStat
	o.sum += record.GetTotalDurationMills()

	o.Count++

	statefulMsg, hasStatus := record.Response().(protocol.StatusfulMessage)
	if hasStatus {
		if statefulMsg.Status() != protocol.SuccessStatus {
			o.FailedCount++
		}
	}

	o.Max = float32(math.Max(float64(o.Max), record.GetTotalDurationMills()))

	for metricType, enabled := range a.ShowOption.EnabledMetricTypeSet {
		if enabled {
			samples := a.samplesMap[MetricType(metricType)]
			MetricExtract := GetMetricExtractFunc[float64](MetricType(metricType))
			AddToSamples(samples, record, MetricExtract, a.SampleLimit)

			percentileCalculator := a.percentileCalculators[MetricType(metricType)]
			percentileCalculator.AddValue(MetricExtract(record))
		}
	}

	o.Avg = float32(o.sum / float64(o.Count))
	return nil
}

func AddToSamples[T MetricValueType](samples []*AnnotatedRecord, newSample *AnnotatedRecord, extractMetric MetricExtract[T], maxSamplesNum int) []*AnnotatedRecord {
	result := samples
	isFull := len(samples) == maxSamplesNum
	idx, _ := slices.BinarySearchFunc(samples, newSample, func(o1 *AnnotatedRecord, o2 *AnnotatedRecord) int {
		t1, t2 := extractMetric(o1), extractMetric(o2)
		return cmp.Compare(t1, t2)
	})
	// at the front and the samples is full
	if isFull && idx == 0 {
		return result
	}
	result = slices.Insert(samples, idx, newSample)
	for len(result) > maxSamplesNum {
		result = result[maxSamplesNum-1:]
	}
	return result
}

type Analyzer struct {
	Classfier
	*ShowOption
	common.SideEnum // 那一边的统计指标TODO 根据参数自动推断
	Aggregators     map[classId]aggregator
	recordsChannel  <-chan *AnnotatedRecord
}

func CreateAnalyzer(recordsChannel <-chan *AnnotatedRecord, classfier Classfier, showOption *ShowOption) *Analyzer {
	return &Analyzer{
		Classfier:      getClassfier(showOption.ClassfierType),
		recordsChannel: recordsChannel,
		Aggregators:    make(map[classId]aggregator),
		ShowOption:     showOption,
	}
}

func (a *Analyzer) analyze(record *AnnotatedRecord) {
	class, err := a.Classfier(record)
	if err == nil {
		aggregator, exists := a.Aggregators[class]
		if !exists {
			a.Aggregators[class] = createAggregator(class, a.ShowOption)
			aggregator = a.Aggregators[class]
		}
		aggregator.receive(record)
	} else {
		log.Errorf("classify error: %v\n", err)
	}
}
