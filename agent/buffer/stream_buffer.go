package buffer

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/emirpasic/gods/maps/treemap"
)

var maxBytesGap int = 1024 * 1024 * 1

type StreamBuffer struct {
	buffers    []*Buffer
	capacity   int
	timestamps *treemap.Map
}

func New(capacity int) *StreamBuffer {

	return &StreamBuffer{
		buffers:  make([]*Buffer, 0),
		capacity: capacity,
		timestamps: treemap.NewWith(func(a, b interface{}) int {
			ai := a.(uint64)
			bi := b.(uint64)
			return cmp.Compare(ai, bi)
		}),
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

func (sb *StreamBuffer) Position0() int {
	if sb.IsEmpty() {
		return 0
	}
	return int(sb.buffers[0].seq)
}

func (sb *StreamBuffer) PositionN() int {
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
	sb.timestamps.Clear()
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
func (sb *StreamBuffer) RemoveHead() {
	sb.RemovePrefix(sb.Head().Len())
}
func (sb *StreamBuffer) IsContinugous() bool {
	return len(sb.buffers) == 1
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
	for !sb.IsEmpty() && sb.PositionN()-sb.Position0() > sb.capacity {
		lastDelete = sb.buffers[0]
		sb.buffers = sb.buffers[1:]
	}
	if lastDelete != nil {
		sb.cleanTimestampMapBySeqNoMoreThan(lastDelete.seq)
	}
}
func (sb *StreamBuffer) cleanTimestampMapBySeqNoMoreThan(targetSeq uint64) {
	needsDelete := make([]uint64, 0)
	it := sb.timestamps.Iterator()
	for it.Next() {
		seq := it.Key().(uint64)
		if seq < targetSeq {
			needsDelete = append(needsDelete, seq)
		} else {
			break
		}
	}
	for _, seq := range needsDelete {
		sb.timestamps.Remove(seq)
	}
}

func (sb *StreamBuffer) FindTimestampBySeq(targetSeq uint64) (uint64, bool) {
	key, value := sb.timestamps.Floor(targetSeq)
	if key == nil {
		return 0, false
	}
	return value.(uint64), true
}

func (sb *StreamBuffer) Add(seq uint64, data []byte, timestamp uint64) {
	dataLen := uint64(len(data))
	newBuffer := &Buffer{
		buf: data,
		seq: seq,
	}
	if sb.IsEmpty() {
		sb.updateTimestamp(seq, timestamp)
		sb.buffers = append(sb.buffers, newBuffer)
		return
	}
	if sb.Position0()-int(seq) >= maxBytesGap {
		return
	}
	if int(seq)-sb.PositionN() >= maxBytesGap {
		sb.Clear()
		sb.buffers = append(sb.buffers, newBuffer)
		sb.updateTimestamp(seq, timestamp)
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
	sb.updateTimestamp(seq, timestamp)
	sb.shrinkBufferUntilSizeBelowCapacity()
}

func (sb *StreamBuffer) updateTimestamp(seq uint64, timestamp uint64) {
	sb.timestamps.Put(seq, timestamp)
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
