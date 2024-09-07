package conn

import (
	"kyanos/monitor"
	"sync/atomic"
)

var _ monitor.MetricExporter = &ConnManager{}

func (c *ConnManager) ExportMetrics() monitor.MetricMap {
	var count int64 = 0
	c.connMap.Range(func(key, value any) bool {
		atomic.AddInt64(&count, 1)
		return true
	})
	return monitor.MetricMap{
		"conn_added_num":  float64(c.connectionAdded),
		"conn_closed_num": float64(c.connectionClosed),
		"conn_num":        float64(count),
	}
}

func (c *ConnManager) MetricGroupName() string {
	return "conn_manager"
}
