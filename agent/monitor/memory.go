package monitor

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"kyanos/common"
)

// MemoryStats holds memory usage information
type MemoryStats struct {
	AllocMB      float64
	TotalAllocMB float64
	SysMB        float64
	NumGC        uint32
	Goroutines   int
	Timestamp    time.Time
}

// MemoryMonitor provides memory monitoring capabilities
type MemoryMonitor struct {
	interval     time.Duration
	maxMemoryMB  float64
	maxGoroutine int
	statsChan    chan MemoryStats
	alertHandler func(alert string)
}

// MemoryMonitorOptions configures the memory monitor
type MemoryMonitorOptions struct {
	Interval     time.Duration
	MaxMemoryMB  float64
	MaxGoroutine int
}

// NewMemoryMonitor creates a new memory monitor
func NewMemoryMonitor(opts MemoryMonitorOptions) *MemoryMonitor {
	if opts.Interval == 0 {
		opts.Interval = 10 * time.Second
	}
	if opts.MaxMemoryMB == 0 {
		opts.MaxMemoryMB = 1024 // 1GB default
	}
	if opts.MaxGoroutine == 0 {
		opts.MaxGoroutine = 10000
	}

	return &MemoryMonitor{
		interval:     opts.Interval,
		maxMemoryMB:  opts.MaxMemoryMB,
		maxGoroutine: opts.MaxGoroutine,
		statsChan:    make(chan MemoryStats, 100),
	}
}

// SetAlertHandler sets a custom alert handler
func (m *MemoryMonitor) SetAlertHandler(handler func(alert string)) {
	m.alertHandler = handler
}

// Stats returns the stats channel
func (m *MemoryMonitor) Stats() <-chan MemoryStats {
	return m.statsChan
}

// Start begins monitoring memory usage
func (m *MemoryMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := m.collectStats()
			
			// Check thresholds and alert
			m.checkThresholds(stats)
			
			// Send stats (non-blocking)
			select {
			case m.statsChan <- stats:
			default:
				// Channel full, skip
			}
		}
	}
}

// collectStats collects current memory statistics
func (m *MemoryMonitor) collectStats() MemoryStats {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return MemoryStats{
		AllocMB:      float64(memStats.Alloc) / 1024 / 1024,
		TotalAllocMB: float64(memStats.TotalAlloc) / 1024 / 1024,
		SysMB:        float64(memStats.Sys) / 1024 / 1024,
		NumGC:        memStats.NumGC,
		Goroutines:   runtime.NumGoroutine(),
		Timestamp:    time.Now(),
	}
}

// checkThresholds checks if memory usage exceeds thresholds
func (m *MemoryMonitor) checkThresholds(stats MemoryStats) {
	var alerts []string

	if stats.AllocMB > m.maxMemoryMB {
		alerts = append(alerts, fmt.Sprintf("Memory usage too high: %.2f MB (threshold: %.2f MB)", 
			stats.AllocMB, m.maxMemoryMB))
	}

	if stats.Goroutines > m.maxGoroutine {
		alerts = append(alerts, fmt.Sprintf("Too many goroutines: %d (threshold: %d)", 
			stats.Goroutines, m.maxGoroutine))
	}

	for _, alert := range alerts {
		common.AgentLog.Warnf("[MemoryMonitor] %s", alert)
		if m.alertHandler != nil {
			m.alertHandler(alert)
		}
	}
}

// ForceGC forces garbage collection and returns memory freed
func ForceGC() uint64 {
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	runtime.GC()

	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	return before.Alloc - after.Alloc
}

// GetMemoryUsage returns current memory usage in MB
func GetMemoryUsage() float64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	return float64(memStats.Alloc) / 1024 / 1024
}

// GetGoroutineCount returns current goroutine count
func GetGoroutineCount() int {
	return runtime.NumGoroutine()
}
