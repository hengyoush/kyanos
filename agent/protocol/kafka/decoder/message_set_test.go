package decoder_test

import (
	"testing"

	. "kyanos/agent/protocol/kafka/common"
	"kyanos/agent/protocol/kafka/decoder"
	. "kyanos/agent/protocol/kafka/decoder"

	"github.com/stretchr/testify/assert"
)

func TestExtractRecordMessage(t *testing.T) {
	// Empty key and value Record.
	{
		input := []byte("\x0c\x00\x00\x00\x01\x00\x00")
		expectedResult := RecordMessage{}
		decoder := decoder.NewPacketDecoder(input)
		result, err := decoder.ExtractRecordMessage()
		assert.NoError(t, err)
		assert.Equal(t, expectedResult, result)
	}
	{
		input := []byte("\x28\x00\x00\x00\x06key\x1cMy first event\x00")
		expectedResult := RecordMessage{Key: "key", Value: "My first event"}
		decoder := NewPacketDecoder(input)
		result, err := decoder.ExtractRecordMessage()
		assert.NoError(t, err)
		assert.Equal(t, expectedResult, result)
	}
}

func TestExtractRecordBatchV8(t *testing.T) {
	input := []byte(
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x46\xff\xff\xff\xff\x02\xa7\x88\x71\xd8\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x01\x7a\xb2\x0a\x70\x1d\x00\x00\x01\x7a\xb2\x0a\x70\x1d\xff" +
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x01\x28\x00\x00\x00\x01" +
			"\x1c\x4d\x79\x20\x66\x69\x72\x73\x74\x20\x65\x76\x65\x6e\x74\x00")
	expectedResult := RecordBatch{Records: []RecordMessage{{Key: "", Value: "My first event"}}}
	decoder := NewPacketDecoder(input)
	decoder.SetAPIInfo(KProduce, 8)
	var batchLength int32
	result, err := decoder.ExtractRecordBatch(&batchLength)
	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
}

func TestExtractRecordBatchV9(t *testing.T) {
	input := []byte(
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4e\xff\xff\xff\xff\x02\xc0\xde\x91\x11\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x01\x7a\x1b\xc8\x2d\xaa\x00\x00\x01\x7a\x1b\xc8\x2d\xaa\xff" +
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x01\x38\x00\x00\x00\x01" +
			"\x2c\x54\x68\x69\x73\x20\x69\x73\x20\x6d\x79\x20\x66\x69\x72\x73\x74\x20\x65\x76\x65\x6e" +
			"\x74\x00")
	expectedResult := RecordBatch{Records: []RecordMessage{{Key: "", Value: "This is my first event"}}}
	decoder := NewPacketDecoder(input)
	decoder.SetAPIInfo(KProduce, 9)
	var batchLength int32
	result, err := decoder.ExtractRecordBatch(&batchLength)
	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
}
