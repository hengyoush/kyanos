package buffer_test

import (
	"kyanos/agent/buffer"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStreamBuffer(t *testing.T) {
	sb := buffer.New(10)
	data := []byte{0, 1, 2, 3, 4}
	sb.Add(1, data, 2)

	buffers := sb.Buffers()
	assert.Equal(t, 1, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), data)
}

func TestStreamBuffer2(t *testing.T) {
	sb := buffer.New(1000)
	data := []byte{0, 1, 2, 3, 4}
	sb.Add(1, data, 2)

	data2 := []byte{4, 5, 6, 7, 8}
	sb.Add(10, data2, 3)

	buffers := sb.Buffers()
	assert.Equal(t, 2, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), data)
	b1 := buffers[1]
	assert.Equal(t, b1.Buffer(), data2)
}

func TestStreamBuffer3(t *testing.T) {
	sb := buffer.New(1000)
	data2 := []byte{4, 5, 6, 7, 8}
	sb.Add(10, data2, 3)
	data := []byte{0, 1, 2, 3, 4}
	sb.Add(1, data, 2)

	buffers := sb.Buffers()
	assert.Equal(t, 2, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), data)
	b1 := buffers[1]
	assert.Equal(t, b1.Buffer(), data2)
}

func TestStreamBufferFuseAsRight(t *testing.T) {
	sb := buffer.New(1000)
	data2 := []byte{4, 5, 6, 7, 8}
	sb.Add(6, data2, 3)
	data := []byte{0, 1, 2, 3, 4}
	sb.Add(1, data, 2)

	buffers := sb.Buffers()
	assert.Equal(t, 1, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), append(data, data2...))
}

func TestStreamBufferFuseAsLeft(t *testing.T) {
	sb := buffer.New(1000)
	data := []byte{0, 1, 2, 3, 4}
	sb.Add(1, data, 2)
	data2 := []byte{4, 5, 6, 7, 8}
	sb.Add(6, data2, 3)

	buffers := sb.Buffers()
	assert.Equal(t, 1, len(buffers))
	b := buffers[0]
	assert.Equal(t, b.Buffer(), append(data, data2...))
}
