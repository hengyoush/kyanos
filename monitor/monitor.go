package monitor

import (
	"kyanos/bpf"
	"kyanos/common"
	"sync"
	"time"
)

var log = common.DefaultLog

var enableMonitor = false

type MetricMap map[string]float64

type MetricExporter interface {
	ExportMetrics() MetricMap
	MetricGroupName() string
}

var MetricExporters map[string]MetricExporter
var lock *sync.Mutex
var tiker *time.Ticker

func init() {
	MetricExporters = make(map[string]MetricExporter)
	lock = &sync.Mutex{}
	tiker = time.NewTicker(10 * time.Second)
	if enableMonitor {
		go Run()
	}
	RegisterMetricExporter(&BPFMetricExporter{})
}

func RegisterMetricExporter(e MetricExporter) {
	if !enableMonitor {
		return
	}
	lock.Lock()
	defer lock.Unlock()
	if e == nil {
		return
	}
	MetricExporters[e.MetricGroupName()] = e
}

func UnregisterMetricExporter(e MetricExporter) {
	lock.Lock()
	defer lock.Unlock()
	if e == nil {
		return
	}
	delete(MetricExporters, e.MetricGroupName())
}

func Run() {
	for t := range tiker.C {
		log.Infoln("Tick at", t)
		exporters := MetricExporters
		for _, each := range exporters {
			metrics := each.ExportMetrics()
			log.Infof("[%s]\n", each.MetricGroupName())
			log.Infof("%v\n\n", metrics)
		}
	}

}

type BPFMetricExporter struct {
}

// ExportMetrics implements monitor.MetricExporter.
func (b *BPFMetricExporter) ExportMetrics() MetricMap {

	agentObjs := bpf.Objs.(*bpf.AgentObjects)
	it := agentObjs.ConnInfoMap.Iterate()
	count := 0
	var key uint64
	var value bpf.AgentConnInfoT
	for it.Next(&key, &value) {
		count++
		log.Infoln(connInfoT(value))
	}
	return MetricMap{
		"conn_info_map_size": float64(count),
	}
}

func connInfoT(value bpf.AgentConnInfoT) string {
	// LocalIp := common.IntToBytes(value.Laddr.In4.SinAddr.S_addr)
	// RemoteIp := common.IntToBytes(value.Raddr.In4.SinAddr.S_addr)
	// LocalPort := common.Port(value.Laddr.In4.SinPort)
	// RemotePort := common.Port(value.Raddr.In4.SinPort)
	// return fmt.Sprintf("%s:%d => %s:%d", LocalIp, LocalPort, RemoteIp, RemotePort)
	return "-"
}

// MetricGroupName implements monitor.MetricExporter.
func (b *BPFMetricExporter) MetricGroupName() string {
	return "bpf_map_size"
}

var _ MetricExporter = &BPFMetricExporter{}
