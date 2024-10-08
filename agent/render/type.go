package render

import (
	. "kyanos/agent/analysis/common"
)

var MetricTypeNames = map[MetricType]string{
	ResponseSize:                 "Response Size",
	RequestSize:                  "Request Size",
	TotalDuration:                "Total Duration",
	BlackBoxDuration:             "BlackBox Duration",
	ReadFromSocketBufferDuration: "Socket Read Time",
}

var MetricTypeSampleNames = map[MetricType]string{
	ResponseSize:                 "Max Response Size Samples",
	RequestSize:                  "Max Request Size Samples",
	TotalDuration:                "Max Total Duration",
	BlackBoxDuration:             "Max BlackBox Duration",
	ReadFromSocketBufferDuration: "Max Socket Read Time",
}

var MetricTypeUnit = map[MetricType]string{
	ResponseSize:                 "bytes",
	RequestSize:                  "bytes",
	TotalDuration:                "ms",
	BlackBoxDuration:             "ms",
	ReadFromSocketBufferDuration: "ms",
}
