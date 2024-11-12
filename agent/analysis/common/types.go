package common

import (
	"fmt"
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"
	ac "kyanos/common"

	"golang.org/x/exp/constraints"
)

type AnalysisOptions struct {
	EnabledMetricTypeSet MetricTypeSet
	SampleLimit          int
	Side                 ac.SideEnum
	ClassfierType
	SubClassfierType           ClassfierType
	ProtocolSpecificClassfiers map[bpf.AgentTrafficProtocolT]ClassfierType
	CleanWhenHarvest           bool

	// Fast Inspect Options
	TimeLimit              int
	SlowMode               bool
	BigRespMode            bool
	BigReqMode             bool
	CurrentReceivedSamples func() int
	HavestSignal           chan struct{}

	// overview mode
	Overview bool
}

func (a *AnalysisOptions) Init() {
	if a.SampleLimit <= 0 {
		a.SampleLimit = 10
	}
	a.HavestSignal = make(chan struct{}, 10)

	if a.EnableBatchModel() {
		a.CleanWhenHarvest = true
	} else {
		a.CleanWhenHarvest = false
	}
	if a.SlowMode {
		a.EnabledMetricTypeSet = MetricTypeSet{
			TotalDuration: true,
		}
		if a.ClassfierType == Default {
			a.ClassfierType = RemoteIp
		}
	} else if a.BigReqMode || a.BigRespMode {
		if a.BigRespMode {
			a.EnabledMetricTypeSet = MetricTypeSet{
				ResponseSize: true,
			}
		} else {
			a.EnabledMetricTypeSet = MetricTypeSet{
				RequestSize: true,
			}
		}
		if a.ClassfierType == Default {
			a.ClassfierType = RemoteIp
		}
	} else {
		if a.ClassfierType == Default {
			a.ClassfierType = Conn
		}
	}
	// temp disable batch model
	// a.disableBatchModel()
}

func (a AnalysisOptions) EnableBatchModel() bool {
	return a.TimeLimit > 0
	// return a.SlowMode || a.BigReqMode || a.BigRespMode
}

func (a *AnalysisOptions) disableBatchModel() {
	a.SlowMode = false
	a.BigReqMode = false
	a.BigRespMode = false
	a.CleanWhenHarvest = false
}

type ClassfierType int

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
	Start MetricType = iota
	ResponseSize
	RequestSize
	TotalDuration
	BlackBoxDuration
	ReadFromSocketBufferDuration
	NoneType
)

func (m MetricType) IsTotalMeaningful() bool {
	switch m {
	case ResponseSize, RequestSize:
		return true
	default:
		return false
	}
}
func GetMetricExtractFunc[T MetricValueType](t MetricType) MetricExtract[T] {
	switch t {
	case ResponseSize:
		return func(ar *AnnotatedRecord) T {
			return T(ar.RespSize)
		}
	case RequestSize:
		return func(ar *AnnotatedRecord) T { return T(ar.ReqSize) }
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

type LatencyMetric int

const (
	Avg LatencyMetric = iota
	Max
	P50
	P90
	P99
)

type AnnotatedRecord struct {
	common.ConnDesc
	protocol.Record
	StartTs                      uint64
	EndTs                        uint64
	ReqPlainTextSize             int
	RespPlainTextSize            int
	ReqSize                      int
	RespSize                     int
	TotalDuration                float64
	BlackBoxDuration             float64
	CopyToSocketBufferDuration   float64
	ReadFromSocketBufferDuration float64
	ReqSyscallEventDetails       []SyscallEventDetail
	RespSyscallEventDetails      []SyscallEventDetail
	ReqNicEventDetails           []NicEventDetail
	RespNicEventDetails          []NicEventDetail
}

func (a *AnnotatedRecord) GetTotalDurationMills() float64 {
	return common.NanoToMills(int32(a.TotalDuration))
}

func (a *AnnotatedRecord) GetBlackBoxDurationMills() float64 {
	return common.NanoToMills(int32(a.BlackBoxDuration))
}

func (a *AnnotatedRecord) GetReadFromSocketBufferDurationMills() float64 {
	return common.NanoToMills(int32(a.ReadFromSocketBufferDuration))
}

func (a *AnnotatedRecord) GetLastRespSyscallTime() int64 {
	if len(a.RespSyscallEventDetails) == 0 {
		return 0
	} else {
		return int64(a.RespSyscallEventDetails[len(a.RespSyscallEventDetails)-1].Timestamp)
	}
}

type SyscallEventDetail PacketEventDetail
type NicEventDetail struct {
	PacketEventDetail
	Attributes map[string]any
}
type PacketEventDetail struct {
	ByteSize  int
	Timestamp uint64
}

func (r *AnnotatedRecord) BlackboxName() string {
	if r.ConnDesc.Side == common.ServerSide {
		return "process internal duration"
	} else {
		return "network duration"
	}
}

func (r *AnnotatedRecord) SyscallDisplayName(isReq bool) string {
	if isReq {
		if r.ConnDesc.Side == common.ServerSide {
			return "read"
		} else {
			return "write"
		}
	} else {
		if r.ConnDesc.Side == common.ServerSide {
			return "write"
		} else {
			return "read"
		}
	}
}

type AnnotatedRecordToStringOptions struct {
	Nano bool
	protocol.RecordToStringOptions
	MetricTypeSet
	IncludeSyscallStat bool
	IncludeConnDesc    bool
}

func (r *AnnotatedRecord) TimeDetailInfo() string {
	return r.String(AnnotatedRecordToStringOptions{
		IncludeConnDesc: false,
		MetricTypeSet: MetricTypeSet{
			TotalDuration:                true,
			ReadFromSocketBufferDuration: true,
			BlackBoxDuration:             true,
		},
		IncludeSyscallStat: true,
	})
}

func (r *AnnotatedRecord) String(options AnnotatedRecordToStringOptions) string {
	nano := options.Nano
	var result string
	result += r.Record.String(options.RecordToStringOptions)
	result += "\n"
	if options.IncludeConnDesc {
		result += fmt.Sprintf("[conn] [pid=%d][local addr]=%s:%d [remote addr]=%s:%d [side]=%s [ssl]=%v\n",
			r.Pid, r.LocalAddr.String(), r.LocalPort, r.RemoteAddr.String(), r.RemotePort, r.Side.String(), r.IsSsl)
	}
	if _, ok := options.MetricTypeSet[TotalDuration]; ok {
		result += fmt.Sprintf("[total duration] = %.3f(%s)(start=%s, end=%s)\n", common.ConvertDurationToMillisecondsIfNeeded(float64(r.TotalDuration), nano), timeUnitName(nano),
			common.FormatTimestampWithPrecision(r.StartTs, nano),
			common.FormatTimestampWithPrecision(r.EndTs, nano))
	}
	if _, ok := options.MetricTypeSet[ReadFromSocketBufferDuration]; ok {
		result += fmt.Sprintf("[read from sockbuf]=%.3f(%s)\n", common.ConvertDurationToMillisecondsIfNeeded(float64(r.ReadFromSocketBufferDuration), nano),
			timeUnitName(nano))
	}
	if _, ok := options.MetricTypeSet[BlackBoxDuration]; ok {
		result += fmt.Sprintf("[%s]=%.3f(%s)\n", r.BlackboxName(),
			common.ConvertDurationToMillisecondsIfNeeded(float64(r.BlackBoxDuration), nano),
			timeUnitName(nano))
	}

	if options.IncludeSyscallStat {
		result += fmt.Sprintf("[syscall] [%s count]=%d [%s bytes]=%d [%s count]=%d [%s bytes]=%d\n",
			r.SyscallDisplayName(true), len(r.ReqSyscallEventDetails),
			r.SyscallDisplayName(true), r.ReqSize,
			r.SyscallDisplayName(false), len(r.RespSyscallEventDetails),
			r.SyscallDisplayName(false), r.RespSize)
		if r.ConnDesc.IsSsl {
			result += fmt.Sprintf("[ssl][plaintext] [%s bytes]=%d [%s bytes]=%d\n", r.SyscallDisplayName(true), r.ReqPlainTextSize,
				r.SyscallDisplayName(false), r.RespPlainTextSize)
		}
		result += "\n"
	} else {
		if _, ok := options.MetricTypeSet[RequestSize]; ok {
			result += fmt.Sprintf("[syscall] [%s count]=%d [%s bytes]=%d",
				r.SyscallDisplayName(true), len(r.ReqSyscallEventDetails),
				r.SyscallDisplayName(true), r.ReqSize)
			if r.ConnDesc.IsSsl {
				result += fmt.Sprintf("[plaintext bytes]=%d", r.ReqPlainTextSize)
			}
			result += "\n"
		}
		if _, ok := options.MetricTypeSet[ResponseSize]; ok {
			result += fmt.Sprintf("[syscall] [%s count]=%d [%s bytes]=%d",
				r.SyscallDisplayName(false), len(r.RespSyscallEventDetails),
				r.SyscallDisplayName(false), r.RespSize)
			if r.ConnDesc.IsSsl {
				result += fmt.Sprintf("[plaintext bytes]=%d", r.RespPlainTextSize)
			}
			result += "\n"
		}
	}
	return result
}

func timeUnitName(nano bool) string {
	if nano {
		return "ns"
	} else {
		return "ms"
	}
}
