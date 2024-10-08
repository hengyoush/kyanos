package analysis

import (
	"cmp"
	"context"
	analysis_common "kyanos/agent/analysis/common"
	"kyanos/agent/protocol"
	"kyanos/common"
	"math"
	"slices"
	"time"
)

type aggregator struct {
	*analysis_common.AnalysisOptions
	*ConnStat
}

func createAggregatorWithHumanReadableClassId(humanReadableClassId string,
	classId ClassId, aggregateOption *analysis_common.AnalysisOptions) *aggregator {
	aggregator := createAggregator(classId, aggregateOption)
	aggregator.HumanReadbleClassId = humanReadableClassId
	return aggregator
}

func createAggregator(classId ClassId, aggregateOption *analysis_common.AnalysisOptions) *aggregator {
	aggregator := aggregator{}
	aggregator.reset(classId, aggregateOption)
	return &aggregator
}

func (a *aggregator) reset(classId ClassId, aggregateOption *analysis_common.AnalysisOptions) {
	a.AnalysisOptions = aggregateOption
	a.ConnStat = &ConnStat{
		ClassId:       classId,
		ClassfierType: aggregateOption.ClassfierType,
	}
	a.SamplesMap = make(map[analysis_common.MetricType][]*analysis_common.AnnotatedRecord)
	a.PercentileCalculators = make(map[analysis_common.MetricType]*PercentileCalculator)
	a.MaxMap = make(map[analysis_common.MetricType]float32)
	a.SumMap = make(map[analysis_common.MetricType]float64)
	for rawMetricType, enabled := range aggregateOption.EnabledMetricTypeSet {
		if enabled {
			metricType := analysis_common.MetricType(rawMetricType)
			a.PercentileCalculators[metricType] = NewPercentileCalculator()
			a.SamplesMap[metricType] = make([]*analysis_common.AnnotatedRecord, 0)
		}
	}
}

func (a *aggregator) receive(record *analysis_common.AnnotatedRecord) error {
	o := a.ConnStat

	o.Count++

	statefulMsg, hasStatus := record.Response().(protocol.StatusfulMessage)
	if hasStatus {
		if statefulMsg.Status() != protocol.SuccessStatus {
			o.FailedCount++
		}
	}
	a.ConnStat.Side = record.ConnDesc.Side

	for rawMetricType, enabled := range a.AnalysisOptions.EnabledMetricTypeSet {
		metricType := analysis_common.MetricType(rawMetricType)

		if enabled {
			samples := a.SamplesMap[metricType]
			MetricExtract := analysis_common.GetMetricExtractFunc[float64](metricType)
			a.SamplesMap[metricType] = AddToSamples(samples, record, MetricExtract, a.AnalysisOptions.SampleLimit)

			metricValue := MetricExtract(record)

			percentileCalculator := a.PercentileCalculators[metricType]
			percentileCalculator.AddValue(metricValue)

			a.MaxMap[metricType] = float32(math.Max(float64(a.MaxMap[metricType]), float64(metricValue)))
			a.SumMap[metricType] = a.SumMap[metricType] + metricValue
		}
	}
	return nil
}

func AddToSamples[T analysis_common.MetricValueType](samples []*analysis_common.AnnotatedRecord, newSample *analysis_common.AnnotatedRecord, extractMetric analysis_common.MetricExtract[T], maxSamplesNum int) []*analysis_common.AnnotatedRecord {
	result := samples
	isFull := len(samples) == maxSamplesNum
	idx, _ := slices.BinarySearchFunc(samples, newSample, func(o1 *analysis_common.AnnotatedRecord, o2 *analysis_common.AnnotatedRecord) int {
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
	*analysis_common.AnalysisOptions
	common.SideEnum // 那一边的统计指标TODO 根据参数自动推断
	Aggregators     map[ClassId]*aggregator
	recordsChannel  <-chan *analysis_common.AnnotatedRecord
	stopper         <-chan int
	resultChannel   chan<- []*ConnStat
	renderStopper   chan int
	ticker          *time.Ticker
	tickerC         <-chan time.Time
	ctx             context.Context
}

func CreateAnalyzer(recordsChannel <-chan *analysis_common.AnnotatedRecord, showOption *analysis_common.AnalysisOptions, resultChannel chan<- []*ConnStat, renderStopper chan int, ctx context.Context) *Analyzer {
	stopper := make(chan int)
	// ac.AddToFastStopper(stopper)
	analyzer := &Analyzer{
		Classfier:       getClassfier(showOption.ClassfierType),
		recordsChannel:  recordsChannel,
		Aggregators:     make(map[ClassId]*aggregator),
		AnalysisOptions: showOption,
		stopper:         stopper,
		resultChannel:   resultChannel,
		renderStopper:   renderStopper,
	}
	if showOption.Interval > 0 {
		analyzer.ticker = time.NewTicker(time.Second * time.Duration(showOption.Interval))
		analyzer.tickerC = analyzer.ticker.C
	} else {
		analyzer.tickerC = make(<-chan time.Time)
	}
	return analyzer
}

func (a *Analyzer) Run() {
	for {
		select {
		// case <-a.stopper:
		case <-a.ctx.Done():
			if a.AnalysisOptions.Interval == 0 {
				a.resultChannel <- a.harvest()
				time.Sleep(1 * time.Second)
			}
			a.renderStopper <- 1
			return
		case record := <-a.recordsChannel:
			a.analyze(record)
		case <-a.tickerC:
			a.resultChannel <- a.harvest()
		}
	}
}

func (a *Analyzer) harvest() []*ConnStat {
	result := make([]*ConnStat, 0)
	for _, aggregator := range a.Aggregators {
		connstat := aggregator.ConnStat
		// aggregator.reset(classId, a.analysis_common.AnalysisOptions)
		result = append(result, connstat)
	}
	a.Aggregators = make(map[ClassId]*aggregator)
	return result
}

func (a *Analyzer) analyze(record *analysis_common.AnnotatedRecord) {
	class, err := a.Classfier(record)
	if err == nil {
		aggregator, exists := a.Aggregators[class]
		if !exists {
			humanReadableFunc, ok := classIdHumanReadableMap[a.AnalysisOptions.ClassfierType]
			if ok {
				humanReadableClassId := humanReadableFunc(record)
				a.Aggregators[class] = createAggregatorWithHumanReadableClassId(humanReadableClassId,
					class, a.AnalysisOptions)
			} else {
				a.Aggregators[class] = createAggregator(class, a.AnalysisOptions)
			}

			aggregator = a.Aggregators[class]
		}
		aggregator.receive(record)
	} else {
		common.DefaultLog.Warnf("classify error: %v\n", err)
	}
}
