package buffer

import (
	"fmt"
	"slices"
)

var maxBytesGap int = 1024 * 1024 * 1

type StreamBuffer struct {
	buffers  []*Buffer
	capacity int
}

type bufferRelativePostitonType int

const (
	LEFT bufferRelativePostitonType = iota
	LEFT_CROSS
	LEFT_CONTAINS
)

func New(capacity int) *StreamBuffer {
	return &StreamBuffer{
		buffers:  make([]*Buffer, 0),
		capacity: capacity,
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
func (sb *StreamBuffer) shrinkBufferUntilSizeBelowCapacity() {
	for !sb.IsEmpty() && sb.positionN()-sb.position0() > sb.capacity {
		sb.buffers = sb.buffers[1:]
	}
}
func (sb *StreamBuffer) Add(seq uint64, data []byte, timestamp uint64) {
	dataLen := uint64(len(data))
	newBuffer := &Buffer{
		buf: data,
		seq: seq,
	}
	if sb.IsEmpty() {
		sb.buffers = append(sb.buffers, newBuffer)
		return
	}
	if sb.position0()-int(seq) >= maxBytesGap {
		return
	}
	if int(seq)-sb.positionN() >= maxBytesGap {
		sb.Clear()
		sb.buffers = append(sb.buffers, newBuffer)
		return
	}

	leftIndex, leftBuffer := sb.FindLeftBufferBySeq(seq)
	rightIndex, rightBuffer := sb.FindRightBufferBySeq(seq)
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
			leftBuffer.FuseAsLeft(rightBuffer.seq, rightBuffer.buf)
			sb.buffers = slices.Delete(sb.buffers, rightIndex, rightIndex+1)
		} else if leftBuffer.CanFuseAsLeft(seq, dataLen) && !rightBuffer.CanFuseAsRight(seq, dataLen) {
			leftBuffer.FuseAsLeft(seq, data)
		} else if !leftBuffer.CanFuseAsLeft(seq, dataLen) && rightBuffer.CanFuseAsRight(seq, dataLen) {
			rightBuffer.FuseAsRight(seq, data)
		} else {
			sb.buffers = slices.Insert(sb.buffers, leftIndex+1, newBuffer)
		}
	}

	sb.shrinkBufferUntilSizeBelowCapacity()
}

func (sb *StreamBuffer) FindLeftBufferBySeq(seq uint64) (int, *Buffer) {
	var prev *Buffer
	for index, each := range sb.buffers {
		if each.LeftBoundary() > seq {
			return index - 1, prev
		}
		prev = each
	}
	return len(sb.buffers) - 1, prev
}

func (sb *StreamBuffer) FindRightBufferBySeq(seq uint64) (int, *Buffer) {
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
