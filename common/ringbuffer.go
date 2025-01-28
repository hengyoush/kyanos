package common

import "errors"

var (
	ErrRingBufferFull  = errors.New("ring buffer is full")
	ErrRingBufferEmpty = errors.New("ring buffer is empty")
)

// RingBuffer represents a ring buffer.
type RingBuffer struct {
	data       []any
	size       int
	start, end int
	isFull     bool
}

// NewRingBuffer creates a new ring buffer with the given size.
func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		data: make([]any, size),
		size: size,
	}
}

// Write adds an element to the ring buffer.
func (rb *RingBuffer) Write(value any) error {
	if rb.isFull {
		return ErrRingBufferFull
	}
	rb.data[rb.end] = value
	rb.end = (rb.end + 1) % rb.size
	if rb.end == rb.start {
		rb.isFull = true
	}
	return nil
}

// Read removes and returns the oldest element from the ring buffer.
func (rb *RingBuffer) Read() (any, error) {
	if rb.IsEmpty() {
		return nil, ErrRingBufferEmpty
	}
	value := rb.data[rb.start]
	rb.data[rb.start] = nil
	rb.start = (rb.start + 1) % rb.size
	rb.isFull = false
	return value, nil
}

// IsEmpty checks if the ring buffer is empty.
func (rb *RingBuffer) IsEmpty() bool {
	return !rb.isFull && rb.start == rb.end
}

// IsFull checks if the ring buffer is full.
func (rb *RingBuffer) IsFull() bool {
	return rb.isFull
}

// Size returns the number of elements in the ring buffer.
func (rb *RingBuffer) Size() int {
	if rb.isFull {
		return rb.size
	}
	if rb.end >= rb.start {
		return rb.end - rb.start
	}
	return rb.size - rb.start + rb.end
}

// Peek returns the oldest element without removing it from the ring buffer.
func (rb *RingBuffer) Peek() (any, error) {
	if rb.IsEmpty() {
		return nil, ErrRingBufferEmpty
	}
	return rb.data[rb.start], nil
}

// ReadIndex retrieves the value at the specified index without removing it.
func (rb *RingBuffer) ReadIndex(index int) (any, error) {
	if index < 0 || index >= rb.Size() {
		return nil, errors.New("index out of range")
	}
	actualIndex := (rb.start + index) % rb.size
	return rb.data[actualIndex], nil
}

// Insert adds an element at the specified index in the ring buffer.
func (rb *RingBuffer) Insert(index int, value any) error {
	if index < 0 || index > rb.Size() {
		return errors.New("index out of range")
	}
	if rb.isFull {
		return ErrRingBufferFull
	}

	// Calculate the actual index in the underlying array
	actualIndex := (rb.start + index) % rb.size

	// Shift elements to the right to make space for the new element
	for i := rb.Size(); i > index; i-- {
		rb.data[(rb.start+i)%rb.size] = rb.data[(rb.start+i-1)%rb.size]
	}

	// Insert the new element
	rb.data[actualIndex] = value
	rb.end = (rb.end + 1) % rb.size
	if rb.end == rb.start {
		rb.isFull = true
	}
	return nil
}

// BinarySearch performs a binary search on the ring buffer.
// It assumes that the buffer is sorted.
func (rb *RingBuffer) BinarySearch(target any, compare func(a, b any) int) (int, bool) {
	if rb.IsEmpty() {
		return 0, false
	}

	low, high := 0, rb.Size()-1
	for low <= high {
		mid := (low + high) / 2
		midValue := rb.data[(rb.start+mid)%rb.size]
		comp := compare(midValue, target)
		if comp == 0 {
			return mid, true
		} else if comp < 0 {
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return low, false
}

// MaxCapacity returns the maximum capacity of the ring buffer.
func (rb *RingBuffer) MaxCapacity() int {
	return rb.size
}

// Clear removes all elements from the ring buffer.
func (rb *RingBuffer) Clear() {
	rb.data = make([]any, rb.size)
	rb.start = 0
	rb.end = 0
	rb.isFull = false
}

// ForEach iterates over all elements in the ring buffer and applies the given function.
// If the function returns false, the iteration stops.
func (rb *RingBuffer) ForEach(action func(any) bool) {
	if rb.IsEmpty() {
		return
	}
	for i := 0; i < rb.Size(); i++ {
		index := (rb.start + i) % rb.size
		if !action(rb.data[index]) {
			break
		}
	}
}

// DiscardBeforeIndex discards all elements before the specified index.
func (rb *RingBuffer) DiscardBeforeIndex(index int) error {
	if index < 0 || index >= rb.Size() {
		return errors.New("index out of range")
	}

	// Calculate the actual index in the underlying array
	actualIndex := (rb.start + index) % rb.size

	// Discard elements
	for rb.start != actualIndex {
		rb.data[rb.start] = nil
		rb.start = (rb.start + 1) % rb.size
		rb.isFull = false
	}
	return nil
}
