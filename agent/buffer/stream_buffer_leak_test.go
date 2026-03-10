package buffer

import (
	"math/rand"
	"runtime"
	"testing"
	"time"
)

func TestStreamBufferTimestampCleanup(t *testing.T) {
	sb := New(1024 * 1024) // 1MB capacity

	// Add more entries than maxTimestampEntries
	for i := 0; i < maxTimestampEntries*2; i++ {
		seq := uint64(i * 100)
		data := make([]byte, 10)
		timestamp := uint64(time.Now().UnixNano())
		sb.Add(seq, data, timestamp)
	}

	// Check that timestamps map size is bounded
	if sb.timestamps.Size() > maxTimestampEntries {
		t.Errorf("Timestamps map size %d exceeds max %d", 
			sb.timestamps.Size(), maxTimestampEntries)
	}
}

func TestStreamBufferNoMemoryLeak(t *testing.T) {
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	sb := New(1024 * 1024)

	// Simulate continuous packet processing
	for i := 0; i < 100000; i++ {
		seq := uint64(rand.Intn(1000000))
		data := make([]byte, rand.Intn(100)+10)
		timestamp := uint64(time.Now().UnixNano())
		sb.Add(seq, data, timestamp)

		// Occasionally remove data to simulate normal operation
		if i%1000 == 0 && !sb.IsEmpty() {
			sb.RemoveHead()
		}
	}

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	// Memory growth should be bounded
	growth := int64(m2.Alloc) - int64(m1.Alloc)
	growthMB := float64(growth) / 1024 / 1024

	t.Logf("Memory growth: %.2f MB", growthMB)

	// Allow up to 10MB growth (generous for this test)
	if growthMB > 10 {
		t.Errorf("Potential memory leak: %.2f MB growth", growthMB)
	}
}

func TestStreamBufferClear(t *testing.T) {
	sb := New(1024 * 1024)

	// Add some data
	for i := 0; i < 1000; i++ {
		seq := uint64(i * 100)
		data := make([]byte, 50)
		sb.Add(seq, data, uint64(i))
	}

	// Clear
	sb.Clear()

	// Verify everything is cleared
	if !sb.IsEmpty() {
		t.Error("Buffer should be empty after Clear()")
	}
	if sb.timestamps.Size() != 0 {
		t.Errorf("Timestamps should be empty, got %d", sb.timestamps.Size())
	}
}

func BenchmarkStreamBufferAdd(b *testing.B) {
	sb := New(1024 * 1024)
	data := make([]byte, 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := uint64(i)
		sb.Add(seq, data, uint64(i))
	}
}

func BenchmarkStreamBufferAddWithCleanup(b *testing.B) {
	sb := New(1024 * 1024)
	data := make([]byte, 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := uint64(i)
		sb.Add(seq, data, uint64(i))
		
		// Simulate periodic cleanup trigger
		if i%maxTimestampEntries == 0 {
			sb.cleanOldTimestamps()
		}
	}
}
