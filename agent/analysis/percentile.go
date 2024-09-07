package analysis

import "math"

// PercentileCalculator 使用不等长的桶来计算 百分位值
type PercentileCalculator struct {
	buckets     []int     // 每个桶的计数
	boundaries  []float64 // 每个桶的边界
	totalValues int       // 所有数值的总数
}

// NewPercentileCalculator 初始化一个新的 百分位值 计算器，桶的范围按指数增长
func NewPercentileCalculator() *PercentileCalculator {
	// 定义不等长的桶边界
	boundaries := []float64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096}
	p := &PercentileCalculator{
		buckets:     make([]int, len(boundaries)+1), // 每个边界一个桶，外加一个超过最大边界的桶
		boundaries:  boundaries,
		totalValues: 0,
	}
	return p
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

// Calculate百分位值 计算并返回当前的 百分位值 线
func (p *PercentileCalculator) CalculatePercentile(line float64) float64 {

	if p.totalValues == 0 {
		return 0.0
	}

	// 计算目标位置
	percentileIndex := int(math.Ceil(line * float64(p.totalValues)))

	// 找到 百分位值 所在的桶
	count := 0
	for i, bucketCount := range p.buckets {
		count += bucketCount
		if count >= percentileIndex {
			// 如果是最后一个桶，返回一个较大的估计值
			if i == len(p.boundaries) {
				return p.boundaries[len(p.boundaries)-1] * 2
			}
			percent := 1 - (float64((count - percentileIndex)) / float64(bucketCount))
			var prevBoundary float64
			if i > 0 {
				prevBoundary = p.boundaries[i-1]
			}
			return percent*(p.boundaries[i]-prevBoundary) + prevBoundary
		}
	}

	return 0.0 // 默认返回值，如果没有数据
}
