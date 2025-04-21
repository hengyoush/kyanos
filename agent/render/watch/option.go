package watch

import (
	"strings"
)

type WatchOptions struct {
	WideOutput                   bool
	StaticRecord                 bool
	Opts                         string
	DebugOutput                  bool
	JsonOutput                   string
	MaxRecordContentDisplayBytes int
	MaxRecords                   int
	TraceDevEvent                bool
	TraceSocketEvent             bool
	TraceSslEvent                bool
}

func (w *WatchOptions) Init() {
	if w.Opts != "" {
		if strings.Contains(w.Opts, "wide") {
			w.WideOutput = true
		}
	}
	if w.MaxRecordContentDisplayBytes <= 0 {
		w.MaxRecordContentDisplayBytes = 1024
	}
	if w.MaxRecords <= 0 {
		w.MaxRecords = 100
	}
}

func (w *WatchOptions) UseTui() bool {
	return !w.DebugOutput && w.JsonOutput == ""
}
