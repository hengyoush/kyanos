package buffer

import (
	"fmt"
	"slices"

	"github.com/elliotchance/orderedmap/v2"
)

var maxBytesGap int = 1024 * 1024 * 1

type StreamBuffer struct {
	buffers    []*Buffer
	capacity   int
	timestamps *orderedmap.OrderedMap[uint64, uint64]
}

func New(capacity int) *StreamBuffer {
	return &StreamBuffer{
		buffers:    make([]*Buffer, 0),
		capacity:   capacity,
		timestamps: orderedmap.NewOrderedMap[uint64, uint64](),
	}
}

func (sb *StreamBuffer) Head() *Buffer {
	if sb.IsEmpty() {
		return nil
	} else {
		return sb.buffers[0]
	}
}

func (sb *StreamBuffer) Buffers() []*Buffer {
	return sb.buffers
}

func (sb *StreamBuffer) position0() int {
	if sb.IsEmpty() {
		return 0
	}
	return int(sb.buffers[0].seq)
}

func (sb *StreamBuffer) positionN() int {
	if sb.IsEmpty() {
		return 0
	}
	lastBuffer := sb.buffers[len(sb.buffers)-1]
	return int(lastBuffer.RightBoundary())
}

func (sb *StreamBuffer) IsEmpty() bool {
	return len(sb.buffers) == 0
}
func (sb *StreamBuffer) Clear() {
	sb.buffers = sb.buffers[:]
}
func (sb *StreamBuffer) RemovePrefix(length int) {
	if sb.IsEmpty() {
		return
	}
	left := length
	for left != 0 {
		head := sb.Head()
		if head.Len() > left {
			head.RemovePrefix(left)
			return
		} else {
			sb.shrinkHeadBuffer()
			left -= head.Len()
		}
	}
}
func (sb *StreamBuffer) shrinkHeadBuffer() {
	if sb.IsEmpty() {
		return
	}

	head := sb.buffers[0]
	sb.buffers = sb.buffers[1:]
	sb.cleanTimestampMapBySeqNoMoreThan(head.seq)
}
func (sb *StreamBuffer) shrinkBufferUntilSizeBelowCapacity() {
	var lastDelete *Buffer
	for !sb.IsEmpty() && sb.positionN()-sb.position0() > sb.capacity {
		lastDelete = sb.buffers[0]
		sb.buffers = sb.buffers[1:]
	}
	if lastDelete != nil {
		sb.cleanTimestampMapBySeqNoMoreThan(lastDelete.seq)
	}
}
func (sb *StreamBuffer) cleanTimestampMapBySeqNoMoreThan(targetSeq uint64) {
	needsDelete := make([]uint64, 0)
	for el := sb.timestamps.Front(); el != nil; el = el.Next() {
		seq := el.Key
		if seq < targetSeq {
			needsDelete = append(needsDelete, seq)
		} else {
			break
		}
	}
	for _, seq := range needsDelete {
		sb.timestamps.Delete(seq)
	}
}

func (sb *StreamBuffer) FindTimestampBySeq(targetSeq uint64) (uint64, bool) {
	result := 0
	for el := sb.timestamps.Front(); el != nil; el = el.Next() {
		seq := el.Key
		if seq <= targetSeq {
			result = int(el.Value)
		} else {
			break
		}
	}
	if result != 0 {
		return uint64(result), true
	} else {
		return 0, false
	}
}

func (sb *StreamBuffer) Add(seq uint64, data []byte, timestamp uint64) {
	dataLen := uint64(len(data))
	newBuffer := &Buffer{
		buf: data,
		seq: seq,
	}
	if sb.IsEmpty() {
		sb.timestamps.Set(seq, timestamp)
		sb.buffers = append(sb.buffers, newBuffer)
		return
	}
	if sb.position0()-int(seq) >= maxBytesGap {
		return
	}
	if int(seq)-sb.positionN() >= maxBytesGap {
		sb.Clear()
		sb.buffers = append(sb.buffers, newBuffer)
		sb.timestamps.Set(seq, timestamp)
		return
	}

	leftIndex, leftBuffer := sb.findLeftBufferBySeq(seq)
	_, rightBuffer := sb.findRightBufferBySeq(seq)
	if leftBuffer == nil && rightBuffer == nil {
		sb.buffers = append(sb.buffers, newBuffer)
	} else if leftBuffer == nil && rightBuffer != nil {
		if rightBuffer.CanFuseAsRight(seq, dataLen) {
			rightBuffer.FuseAsRight(seq, data)
		} else {
			sb.buffers = slices.Insert(sb.buffers, 0, newBuffer)
		}
	} else if leftBuffer != nil && rightBuffer == nil {
		if leftBuffer.CanFuseAsLeft(seq, dataLen) {
			leftBuffer.FuseAsLeft(seq, data)
		} else {
			sb.buffers = append(sb.buffers, newBuffer)
		}
	} else {
		if leftBuffer.CanFuseAsLeft(seq, dataLen) && rightBuffer.CanFuseAsRight(seq, dataLen) {
			leftBuffer.FuseAsLeft(seq, data)
			rightBuffer.FuseAsRight(leftBuffer.seq, leftBuffer.buf)
			sb.buffers = slices.Delete(sb.buffers, leftIndex, leftIndex+1)
		} else if leftBuffer.CanFuseAsLeft(seq, dataLen) && !rightBuffer.CanFuseAsRight(seq, dataLen) {
			leftBuffer.FuseAsLeft(seq, data)
		} else if !leftBuffer.CanFuseAsLeft(seq, dataLen) && rightBuffer.CanFuseAsRight(seq, dataLen) {
			rightBuffer.FuseAsRight(seq, data)
		} else {
			sb.buffers = slices.Insert(sb.buffers, leftIndex+1, newBuffer)
		}
	}
	sb.timestamps.Set(seq, timestamp)
	sb.shrinkBufferUntilSizeBelowCapacity()
}

func (sb *StreamBuffer) findLeftBufferBySeq(seq uint64) (int, *Buffer) {
	var prev *Buffer
	for index, each := range sb.buffers {
		if each.LeftBoundary() > seq {
			return index - 1, prev
		}
		prev = each
	}
	return len(sb.buffers) - 1, prev
}

func (sb *StreamBuffer) findRightBufferBySeq(seq uint64) (int, *Buffer) {
	var prev *Buffer
	for index, each := range sb.buffers {
		if each.LeftBoundary() > seq {
			return index, each
		}
	}
	return len(sb.buffers) - 1, prev
}

type Buffer struct {
	buf []byte
	seq uint64
}

func (b *Buffer) Len() int {
	return len(b.buf)
}
func (b *Buffer) Buffer() []byte {
	return b.buf
}

func (b *Buffer) LeftBoundary() uint64 {
	return b.seq
}

func (b *Buffer) RightBoundary() uint64 {
	return b.seq + uint64(len(b.buf))
}
func (b *Buffer) CanFuseAsLeft(seq uint64, len uint64) bool {
	l := seq
	r := l + len
	return b.RightBoundary() >= seq && b.LeftBoundary() <= seq && r >= b.RightBoundary()
}
func (b *Buffer) CanFuseAsRight(seq uint64, len uint64) bool {
	l := seq
	r := seq + len
	return b.LeftBoundary() <= r && b.RightBoundary() >= r && b.LeftBoundary() >= l
}
func (b *Buffer) FuseAsLeft(seq uint64, data []byte) {
	l := seq
	r := l + uint64(len(data))
	if seq == b.RightBoundary() {
		b.buf = append(b.buf, data...)
	} else if seq < b.RightBoundary() && seq >= b.LeftBoundary() {
		overlapSize := b.RightBoundary() - seq
		data = data[overlapSize:]
		b.buf = append(b.buf, data...)
	} else {
		panic(fmt.Sprintf("FuseAsLeft error, buffer left: %d, right: %d, new buffer left: %d, new buffer right: %d", b.LeftBoundary(), b.RightBoundary(), seq, r))
	}
}

func (b *Buffer) FuseAsRight(seq uint64, data []byte) {
	l := seq
	r := l + uint64(len(data))
	if r == b.LeftBoundary() {
		b.seq = seq
		b.buf = append(data, b.buf...)
	} else if r > b.LeftBoundary() && r <= b.RightBoundary() {
		overlapSize := r - b.LeftBoundary()
		data = data[:uint64(len(data))-uint64(overlapSize)]
		b.seq = seq
		b.buf = append(data, b.buf...)
	} else {
		panic(fmt.Sprintf("FuseAsLeft error, buffer left: %d, right: %d, new buffer left: %d, new buffer right: %d", b.LeftBoundary(), b.RightBoundary(), seq, r))
	}
}

func (b *Buffer) RemovePrefix(len int) {
	if b.Len() > len {
		b.buf = b.buf[len:]
		b.seq += uint64(len)
	} else if b.Len() == len {
		return
	} else {
		panic("try to remove size greater than me")
	}
}
