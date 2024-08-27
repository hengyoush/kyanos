package filter

type LatencyFilter struct {
	MinLatency float64
}

func (filter LatencyFilter) Filter(latency float64) bool {
	if filter.MinLatency <= 0 {
		return true
	}
	return latency >= filter.MinLatency
}

type SizeFilter struct {
	MinReqSize  int64
	MinRespSize int64
}

func (filter SizeFilter) FilterByReqSize(reqSize int64) bool {
	if filter.MinReqSize <= 0 {
		return true
	}
	return reqSize >= filter.MinReqSize
}

func (filter SizeFilter) FilterByRespSize(respSize int64) bool {
	if filter.MinRespSize <= 0 {
		return true
	}
	return respSize >= filter.MinRespSize
}
