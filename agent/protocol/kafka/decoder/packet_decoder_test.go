package decoder_test

import (
	"math"
	"testing"

	// . "kyanos/agent/protocol/kafka/common"
	. "kyanos/agent/protocol/kafka/decoder"

	"github.com/stretchr/testify/assert"
)

type PacketDecoderTestCase[T any] struct {
	Input          []byte
	ExpectedOutput T
}

func TestExtractUnsignedVarint(t *testing.T) {
	testCases := []PacketDecoderTestCase[int32]{
		{Input: []byte{0x00}, ExpectedOutput: 0},
		{Input: []byte{0x03}, ExpectedOutput: 3},
		{Input: []byte{0x96, 0x01}, ExpectedOutput: 150},
		{Input: []byte{0xff, 0xff, 0xff, 0xff, 0x0f}, ExpectedOutput: -1},
		{Input: []byte{0x80, 0xC0, 0xFF, 0xFF, 0x0F}, ExpectedOutput: -8192},
		{Input: []byte{0xff, 0xff, 0xff, 0xff, 0x07}, ExpectedOutput: math.MaxInt32},
		{Input: []byte{0x80, 0x80, 0x80, 0x80, 0x08}, ExpectedOutput: math.MinInt32},
	}

	for _, tc := range testCases {
		decoder := NewPacketDecoder(tc.Input)
		result, err := decoder.ExtractUnsignedVarint()
		assert.NoError(t, err)
		assert.Equal(t, tc.ExpectedOutput, result)
	}
}

func TestExtractVarint(t *testing.T) {
	testCases := []PacketDecoderTestCase[int32]{
		{Input: []byte{0x00}, ExpectedOutput: 0},
		{Input: []byte{0x01}, ExpectedOutput: -1},
		{Input: []byte{0x02}, ExpectedOutput: 1},
		{Input: []byte{0x7E}, ExpectedOutput: 63},
		{Input: []byte{0x7F}, ExpectedOutput: -64},
		{Input: []byte{0x80, 0x01}, ExpectedOutput: 64},
		{Input: []byte{0x81, 0x01}, ExpectedOutput: -65},
		{Input: []byte{0xFE, 0x7F}, ExpectedOutput: 8191},
		{Input: []byte{0xFF, 0x7F}, ExpectedOutput: -8192},
		{Input: []byte{0x80, 0x80, 0x01}, ExpectedOutput: 8192},
		{Input: []byte{0x81, 0x80, 0x01}, ExpectedOutput: -8193},
		{Input: []byte{0xFE, 0xFF, 0x7F}, ExpectedOutput: 1048575},
		{Input: []byte{0xFF, 0xFF, 0x7F}, ExpectedOutput: -1048576},
		{Input: []byte{0x80, 0x80, 0x80, 0x01}, ExpectedOutput: 1048576},
		{Input: []byte{0x81, 0x80, 0x80, 0x01}, ExpectedOutput: -1048577},
		{Input: []byte{0xFE, 0xFF, 0xFF, 0x7F}, ExpectedOutput: 134217727},
		{Input: []byte{0xFF, 0xFF, 0xFF, 0x7F}, ExpectedOutput: -134217728},
		{Input: []byte{0x80, 0x80, 0x80, 0x80, 0x01}, ExpectedOutput: 134217728},
		{Input: []byte{0x81, 0x80, 0x80, 0x80, 0x01}, ExpectedOutput: -134217729},
		{Input: []byte{0xFE, 0xFF, 0xFF, 0xFF, 0x0F}, ExpectedOutput: math.MaxInt32},
		{Input: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}, ExpectedOutput: math.MinInt32},
	}

	for _, tc := range testCases {
		decoder := NewPacketDecoder(tc.Input)
		result, err := decoder.ExtractVarint()
		assert.NoError(t, err)
		assert.Equal(t, tc.ExpectedOutput, result)
	}
}

func TestExtractVarlong(t *testing.T) {
	testCases := []PacketDecoderTestCase[int64]{
		{Input: []byte{0x00}, ExpectedOutput: 0},
		{Input: []byte{0x01}, ExpectedOutput: -1},
		{Input: []byte{0x02}, ExpectedOutput: 1},
		{Input: []byte{0x7E}, ExpectedOutput: 63},
		{Input: []byte{0x7F}, ExpectedOutput: -64},
		{Input: []byte{0x80, 0x01}, ExpectedOutput: 64},
		{Input: []byte{0x81, 0x01}, ExpectedOutput: -65},
		{Input: []byte{0xFE, 0x7F}, ExpectedOutput: 8191},
		{Input: []byte{0xFF, 0x7F}, ExpectedOutput: -8192},
		{Input: []byte{0x80, 0x80, 0x01}, ExpectedOutput: 8192},
		{Input: []byte{0x81, 0x80, 0x01}, ExpectedOutput: -8193},
		{Input: []byte{0xFE, 0xFF, 0x7F}, ExpectedOutput: 1048575},
		{Input: []byte{0xFF, 0xFF, 0x7F}, ExpectedOutput: -1048576},
		{Input: []byte{0x80, 0x80, 0x80, 0x01}, ExpectedOutput: 1048576},
		{Input: []byte{0x81, 0x80, 0x80, 0x01}, ExpectedOutput: -1048577},
		{Input: []byte{0xFE, 0xFF, 0xFF, 0x7F}, ExpectedOutput: 134217727},
		{Input: []byte{0xFF, 0xFF, 0xFF, 0x7F}, ExpectedOutput: -134217728},
		{Input: []byte{0x80, 0x80, 0x80, 0x80, 0x01}, ExpectedOutput: 134217728},
		{Input: []byte{0x81, 0x80, 0x80, 0x80, 0x01}, ExpectedOutput: -134217729},
		{Input: []byte{0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}, ExpectedOutput: math.MaxInt64},
		{Input: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}, ExpectedOutput: math.MinInt64},
	}

	for _, tc := range testCases {
		decoder := NewPacketDecoder(tc.Input)
		result, err := decoder.ExtractVarlong()
		assert.NoError(t, err)
		assert.Equal(t, tc.ExpectedOutput, result)
	}
}
