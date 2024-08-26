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
