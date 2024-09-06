package stat

import (
	"math"
)

// PercentileCalculator 使用不等长的桶来计算 P99
type PercentileCalculator struct {
	buckets     []int     // 每个桶的计数
	boundaries  []float64 // 每个桶的边界
	totalValues int       // 所有数值的总数
}

// NewP99Calculator 初始化一个新的 P99 计算器，桶的范围按指数增长
func NewP99Calculator() *PercentileCalculator {
	// 定义不等长的桶边界
	boundaries := []float64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096}

	return &PercentileCalculator{
		buckets:     make([]int, len(boundaries)+1), // 每个边界一个桶，外加一个超过最大边界的桶
		boundaries:  boundaries,
		totalValues: 0,
	}
}

// AddValue 向计算器中添加一个新的值
func (p *PercentileCalculator) AddValue(val float64) {

	// 找到值落入的桶
	bucketIndex := p.findBucket(val)

	// 增加桶的计数
	p.buckets[bucketIndex]++
	p.totalValues++
}

// findBucket 根据值找到对应的桶索引
func (p *PercentileCalculator) findBucket(val float64) int {
	for i, boundary := range p.boundaries {
		if val <= boundary {
			return i
		}
	}
	// 如果超过了最大边界，则放入最后一个桶
	return len(p.boundaries)
}

// CalculateP99 计算并返回当前的 P99 线
func (p *PercentileCalculator) CalculatePercentile(line float64) float64 {

	if p.totalValues == 0 {
		return 0.0
	}

	// 计算目标位置
	p99Index := int(math.Ceil(line * float64(p.totalValues)))

	// 找到 P99 所在的桶
	count := 0
	for i, bucketCount := range p.buckets {
		count += bucketCount
		if count >= p99Index {
			// 如果是最后一个桶，返回一个较大的估计值
			if i == len(p.boundaries) {
				return p.boundaries[len(p.boundaries)-1] * 2
			}
			percent := float64((count - p99Index)) / float64(bucketCount)
			var prevBoundary float64
			if i > 0 {
				prevBoundary = p.boundaries[i-1]
			}
			return percent*(p.boundaries[i]-prevBoundary) + prevBoundary
		}
	}

	return 0.0 // 默认返回值，如果没有数据
}
