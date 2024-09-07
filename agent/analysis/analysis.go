package analysis

import (
	"cmp"
	"kyanos/agent/protocol"
	"kyanos/common"
	"math"
	"slices"
	"time"
)

type AnalysisOptions struct {
	EnabledMetricTypeSet MetricTypeSet
	SampleLimit          int
	DisplayLimit         int
	ClassfierType
}

type aggregator struct {
	*AnalysisOptions
	*ConnStat
}

func createAggregator(classId ClassId, aggregateOption *AnalysisOptions) *aggregator {
	aggregator := aggregator{}
	aggregator.reset(classId, aggregateOption)
	return &aggregator
}

func (a *aggregator) reset(classId ClassId, aggregateOption *AnalysisOptions) {
	a.AnalysisOptions = aggregateOption
	a.ConnStat = &ConnStat{
		ClassId:       classId,
		ClassfierType: aggregateOption.ClassfierType,
	}
	a.SamplesMap = make(map[MetricType][]*AnnotatedRecord)
	a.PercentileCalculators = make(map[MetricType]*PercentileCalculator)
	a.MaxMap = make(map[MetricType]float32)
	a.SumMap = make(map[MetricType]float64)
	for rawMetricType, enabled := range aggregateOption.EnabledMetricTypeSet {
		if enabled {
			metricType := MetricType(rawMetricType)
			a.PercentileCalculators[metricType] = NewP99Calculator()
			a.SamplesMap[metricType] = make([]*AnnotatedRecord, 0)
		}
	}
}

func (a *aggregator) receive(record *AnnotatedRecord) error {
	o := a.ConnStat

	o.Count++

	statefulMsg, hasStatus := record.Response().(protocol.StatusfulMessage)
	if hasStatus {
		if statefulMsg.Status() != protocol.SuccessStatus {
			o.FailedCount++
		}
	}

	for rawMetricType, enabled := range a.AnalysisOptions.EnabledMetricTypeSet {
		metricType := MetricType(rawMetricType)

		if enabled {
			samples := a.SamplesMap[metricType]
			MetricExtract := GetMetricExtractFunc[float64](metricType)
			a.SamplesMap[metricType] = AddToSamples(samples, record, MetricExtract, a.SampleLimit)

			metricValue := MetricExtract(record)

			percentileCalculator := a.PercentileCalculators[metricType]
			percentileCalculator.AddValue(metricValue)

			a.MaxMap[metricType] = float32(math.Max(float64(a.MaxMap[metricType]), float64(metricValue)))
			a.SumMap[metricType] = a.SumMap[metricType] + metricValue
		}
	}
	return nil
}

func AddToSamples[T MetricValueType](samples []*AnnotatedRecord, newSample *AnnotatedRecord, extractMetric MetricExtract[T], maxSamplesNum int) []*AnnotatedRecord {
	result := samples
	isFull := len(samples) == maxSamplesNum
	idx, _ := slices.BinarySearchFunc(samples, newSample, func(o1 *AnnotatedRecord, o2 *AnnotatedRecord) int {
		t1, t2 := extractMetric(o1), extractMetric(o2)
		return cmp.Compare(t1, t2)
	})
	isMin := idx == 0
	// at the front and the samples is full
	if isFull && isMin {
		return result
	}
	result = slices.Insert(samples, idx, newSample)
	for len(result) > maxSamplesNum {
		result = result[1:]
	}
	return result
}

type Analyzer struct {
	Classfier
	*AnalysisOptions
	common.SideEnum // 那一边的统计指标TODO 根据参数自动推断
	Aggregators     map[ClassId]*aggregator
	recordsChannel  <-chan *AnnotatedRecord
	stopper         <-chan int
	resultChannel   chan<- []*ConnStat
	renderStopper   chan int
}

func CreateAnalyzer(recordsChannel <-chan *AnnotatedRecord, showOption *AnalysisOptions, resultChannel chan<- []*ConnStat, renderStopper chan int) *Analyzer {
	stopper := make(chan int, 0)
	common.AddToFastStopper(stopper)
	return &Analyzer{
		Classfier:       getClassfier(showOption.ClassfierType),
		recordsChannel:  recordsChannel,
		Aggregators:     make(map[ClassId]*aggregator),
		AnalysisOptions: showOption,
		stopper:         stopper,
		resultChannel:   resultChannel,
		renderStopper:   renderStopper,
	}
}

func (a *Analyzer) Run() {
	for {
		select {
		case <-a.stopper:
			a.resultChannel <- a.harvest()
			time.Sleep(1 * time.Second)
			a.renderStopper <- 1
			return
		case record := <-a.recordsChannel:
			a.analyze(record)
		}
	}
}

func (a *Analyzer) harvest() []*ConnStat {
	result := make([]*ConnStat, 0)
	for classId, aggregator := range a.Aggregators {
		connstat := aggregator.ConnStat
		aggregator.reset(classId, a.AnalysisOptions)
		result = append(result, connstat)
	}
	return result
}

func (a *Analyzer) analyze(record *AnnotatedRecord) {
	class, err := a.Classfier(record)
	if err == nil {
		aggregator, exists := a.Aggregators[class]
		if !exists {
			a.Aggregators[class] = createAggregator(class, a.AnalysisOptions)
			aggregator = a.Aggregators[class]
		}
		aggregator.receive(record)
	} else {
		log.Errorf("classify error: %v\n", err)
	}
}
