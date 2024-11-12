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
	isSub bool
}

func createAggregatorWithHumanReadableClassId(humanReadableClassId string,
	classId analysis_common.ClassId,
	aggregateOption *analysis_common.AnalysisOptions, isSub bool) *aggregator {
	aggregator := createAggregator(classId, aggregateOption, isSub)
	aggregator.HumanReadbleClassId = humanReadableClassId
	return aggregator
}

func createAggregator(classId analysis_common.ClassId, aggregateOption *analysis_common.AnalysisOptions, isSub bool) *aggregator {
	aggregator := aggregator{}
	aggregator.isSub = isSub
	aggregator.reset(classId, aggregateOption)
	return &aggregator
}

func (a *aggregator) reset(classId analysis_common.ClassId, aggregateOption *analysis_common.AnalysisOptions) {
	a.AnalysisOptions = aggregateOption
	a.ConnStat = &ConnStat{
		ClassId:       classId,
		ClassfierType: aggregateOption.ClassfierType,
		IsSub:         a.isSub,
	}
	if a.isSub {
		a.ConnStat.ClassfierType = aggregateOption.SubClassfierType
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
			MetricExtract := analysis_common.GetMetricExtractFunc[float64](metricType)
			samples := a.SamplesMap[metricType]
			// only sample if aggregator is sub or no sub classfier
			if a.isSub || a.SubClassfierType == analysis_common.None {
				a.SamplesMap[metricType] = AddToSamples(samples, record, MetricExtract, a.AnalysisOptions.SampleLimit)
			} else {
				a.SamplesMap[metricType] = AddToSamples(samples, record, MetricExtract, 1)
			}

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
	subClassfier Classfier
	*analysis_common.AnalysisOptions
	common.SideEnum // 那一边的统计指标TODO 根据参数自动推断
	Aggregators     map[analysis_common.ClassId]*aggregator
	recordsChannel  <-chan *analysis_common.AnnotatedRecord
	stopper         <-chan int
	resultChannel   chan<- []*ConnStat
	renderStopper   chan int
	ticker          *time.Ticker
	tickerC         <-chan time.Time
	ctx             context.Context
	recordReceived  int
}

func CreateAnalyzer(recordsChannel <-chan *analysis_common.AnnotatedRecord, opts *analysis_common.AnalysisOptions, resultChannel chan<- []*ConnStat, renderStopper chan int, ctx context.Context) *Analyzer {
	stopper := make(chan int)
	// ac.AddToFastStopper(stopper)
	opts.Init()
	analyzer := &Analyzer{
		Classfier:       getClassfier(opts.ClassfierType, *opts),
		recordsChannel:  recordsChannel,
		Aggregators:     make(map[analysis_common.ClassId]*aggregator),
		AnalysisOptions: opts,
		stopper:         stopper,
		resultChannel:   resultChannel,
		renderStopper:   renderStopper,
		ctx:             ctx,
	}
	if opts.SubClassfierType != analysis_common.None {
		analyzer.subClassfier = getClassfier(opts.SubClassfierType, *opts)
	}
	opts.CurrentReceivedSamples = func() int {
		return analyzer.recordReceived
	}
	if analyzer.AnalysisOptions.EnableBatchModel() {
		analyzer.tickerC = make(<-chan time.Time)
	} else {
		analyzer.ticker = time.NewTicker(time.Second * 1)
		analyzer.tickerC = analyzer.ticker.C
	}
	return analyzer
}

func (a *Analyzer) Run() {
	defer func() {
		time.Sleep(1 * time.Second)
		go close(a.resultChannel)
	}()
	for {
		select {
		// case <-a.stopper:
		case <-a.ctx.Done():
			a.renderStopper <- 1
			return
		case record := <-a.recordsChannel:
			a.analyze(record)
			a.recordReceived++
			// if a.EnableBatchModel() && a.recordReceived == a.TargetSamples {
			// 	a.resultChannel <- a.harvest()
			// 	return
			// }
		case <-a.AnalysisOptions.HavestSignal:
			a.resultChannel <- a.harvest()
			if a.AnalysisOptions.EnableBatchModel() {
				return
			}
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
	if a.AnalysisOptions.CleanWhenHarvest {
		a.Aggregators = make(map[analysis_common.ClassId]*aggregator)
	}
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
					class, a.AnalysisOptions, false)
			} else {
				a.Aggregators[class] = createAggregator(class, a.AnalysisOptions, false)
			}

			aggregator = a.Aggregators[class]
		}
		aggregator.receive(record)

		if a.subClassfier != nil {
			subClassId, err := a.subClassfier(record)
			if err == nil {
				fullClassId := class + "||" + subClassId
				subAggregator, exists := a.Aggregators[fullClassId]
				if !exists {
					subHumanReadableFunc, ok := getClassIdHumanReadableFunc(a.AnalysisOptions.SubClassfierType, *a.AnalysisOptions)
					if ok {
						subHumanReadableClassId := subHumanReadableFunc(record)
						a.Aggregators[fullClassId] = createAggregatorWithHumanReadableClassId(subHumanReadableClassId, fullClassId, a.AnalysisOptions, true)
					} else {
						a.Aggregators[fullClassId] = createAggregator(fullClassId, a.AnalysisOptions, true)
					}
					subAggregator = a.Aggregators[fullClassId]
				}
				subAggregator.receive(record)
			}
		}
	} else {
		common.DefaultLog.Warnf("classify error: %v\n", err)
	}
}
