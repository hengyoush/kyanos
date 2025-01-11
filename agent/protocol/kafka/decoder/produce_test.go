package decoder_test

import (
	"testing"

	. "kyanos/agent/protocol/kafka/common"
	. "kyanos/agent/protocol/kafka/decoder"

	"github.com/stretchr/testify/assert"
)

func TestExtractProduceReqV7(t *testing.T) {
	input := []byte(
		"\xFF\xFF\x00\x01\x00\x00\x75\x30\x00\x00\x00\x01\x00\x08\x6D\x79\x2D\x74\x6F\x70\x69\x63\x00" +
			"\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x5C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50" +
			"\x00\x00\x00\x00\x02\x76\x7C\xA6\x2F\x00\x00\x00\x00\x00\x01\x00\x00\x01\x7C\x29\x89\x9A\xA2" +
			"\x00\x00\x01\x7C\x29\x89\x9A\xA2\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00" +
			"\x00\x00\x02\x14\x00\x00\x00\x01\x08\x74\x65\x73\x74\x00\x26\x00\x00\x02\x01\x1A\xC2\x48\x6F" +
			"\x6C\x61\x2C\x20\x6D\x75\x6E\x64\x6F\x21\x00")
	recordBatch := RecordBatch{
		Records: []RecordMessage{
			{Key: "", Value: "test"},
			{Key: "", Value: "\xc2Hola, mundo!"},
		},
	}
	messageSet := MessageSet{Size: 92, RecordBatches: []RecordBatch{recordBatch}}
	partition := ProduceReqPartition{Index: 0, MessageSet: messageSet}
	topic := ProduceReqTopic{Name: "my-topic", Partitions: []ProduceReqPartition{partition}}
	expectedResult := ProduceReq{
		TransactionalID: "",
		Acks:            1,
		TimeoutMs:       30000,
		Topics:          []ProduceReqTopic{topic},
	}
	decoder := NewPacketDecoder(input)
	decoder.SetAPIInfo(KProduce, 7)
	result, err := decoder.ExtractProduceReq()
	assert.NoError(t, err)
	assert.True(t, expectedResult.Equal(result))
}

func TestExtractProduceReqV8(t *testing.T) {
	input := []byte(
		"\xff\xff\x00\x01\x00\x00\x05\xdc\x00\x00\x00\x01\x00\x11\x71\x75\x69\x63\x6b\x73\x74\x61" +
			"\x72\x74\x2d\x65\x76\x65\x6e\x74\x73\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x52\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x46\xff\xff\xff\xff\x02\xa7\x88\x71\xd8\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x01\x7a\xb2\x0a\x70\x1d\x00\x00\x01\x7a\xb2\x0a\x70\x1d\xff\xff" +
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x01\x28\x00\x00\x00\x01\x1c" +
			"\x4d\x79\x20\x66\x69\x72\x73\x74\x20\x65\x76\x65\x6e\x74\x00")
	recordBatch := RecordBatch{
		Records: []RecordMessage{
			{Key: "", Value: "My first event"},
		},
	}
	messageSet := MessageSet{Size: 70, RecordBatches: []RecordBatch{recordBatch}}
	partition := ProduceReqPartition{Index: 0, MessageSet: messageSet}
	topic := ProduceReqTopic{Name: "quickstart-events", Partitions: []ProduceReqPartition{partition}}
	expectedResult := ProduceReq{
		TransactionalID: "",
		Acks:            1,
		TimeoutMs:       1500,
		Topics:          []ProduceReqTopic{topic},
	}
	decoder := NewPacketDecoder(input)
	decoder.SetAPIInfo(KProduce, 8)
	result, err := decoder.ExtractProduceReq()
	assert.NoError(t, err)
	assert.True(t, expectedResult.Equal(result))
}

func TestExtractProduceReqV9(t *testing.T) {
	input := []byte(
		"\x00\x00\x01\x00\x00\x05\xdc\x02\x12\x71\x75\x69\x63\x6b\x73\x74\x61\x72\x74\x2d\x65" +
			"\x76\x65\x6e\x74\x73\x02\x00\x00\x00\x00\x5b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x4e\xff\xff\xff\xff\x02\xc0\xde\x91\x11\x00\x00\x00\x00\x00\x00\x00\x00\x01\x7a\x1b\xc8" +
			"\x2d\xaa\x00\x00\x01\x7a\x1b\xc8\x2d\xaa\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
			"\xff\xff\x00\x00\x00\x01\x38\x00\x00\x00\x01\x2c\x54\x68\x69\x73\x20\x69\x73\x20\x6d\x79" +
			"\x20\x66\x69\x72\x73\x74\x20\x65\x76\x65\x6e\x74\x00\x00\x00\x00")
	recordBatch := RecordBatch{
		Records: []RecordMessage{
			{Key: "", Value: "This is my first event"},
		},
	}
	messageSet := MessageSet{Size: 91, RecordBatches: []RecordBatch{recordBatch}}
	partition := ProduceReqPartition{Index: 0, MessageSet: messageSet}
	topic := ProduceReqTopic{Name: "quickstart-events", Partitions: []ProduceReqPartition{partition}}
	expectedResult := ProduceReq{
		TransactionalID: "",
		Acks:            1,
		TimeoutMs:       1500,
		Topics:          []ProduceReqTopic{topic},
	}
	decoder := NewPacketDecoder(input)
	decoder.SetAPIInfo(KProduce, 9)
	result, err := decoder.ExtractProduceReq()
	assert.NoError(t, err)
	assert.True(t, expectedResult.Equal(result))
}

func TestExtractProduceRespV7(t *testing.T) {
	input := []byte(
		"\x00\x00\x00\x01\x00\x08\x6D\x79\x2D\x74\x6F\x70\x69\x63\x00\x00\x00\x01\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x01\xAE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00")
	partition := ProduceRespPartition{
		Index:           0,
		ErrorCode:       0,
		BaseOffset:      430,
		LogAppendTimeMs: -1,
		LogStartOffset:  0,
		RecordErrors:    []RecordError{},
		ErrorMessage:    "",
	}
	topic := ProduceRespTopic{Name: "my-topic", Partitions: []ProduceRespPartition{partition}}
	expectedResult := ProduceResp{
		Topics:         []ProduceRespTopic{topic},
		ThrottleTimeMs: 0,
	}
	decoder := NewPacketDecoder(input)
	decoder.SetAPIInfo(KProduce, 7)
	result, err := decoder.ExtractProduceResp()
	assert.NoError(t, err)
	assert.True(t, expectedResult.Equal(result))
}

func TestExtractProduceRespV8(t *testing.T) {
	input := []byte(
		"\x00\x00\x00\x01\x00\x11\x71\x75\x69\x63\x6b\x73\x74\x61\x72\x74\x2d\x65\x76\x65\x6e\x74" +
			"\x73\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xff\xff\xff" +
			"\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00" +
			"\x00")
	partition := ProduceRespPartition{
		Index:           0,
		ErrorCode:       0,
		BaseOffset:      3,
		LogAppendTimeMs: -1,
		LogStartOffset:  0,
		RecordErrors:    []RecordError{},
		ErrorMessage:    "",
	}
	topic := ProduceRespTopic{Name: "quickstart-events", Partitions: []ProduceRespPartition{partition}}
	expectedResult := ProduceResp{
		Topics:         []ProduceRespTopic{topic},
		ThrottleTimeMs: 0,
	}
	decoder := NewPacketDecoder(input)
	decoder.SetAPIInfo(KProduce, 8)
	result, err := decoder.ExtractProduceResp()
	assert.NoError(t, err)
	assert.True(t, expectedResult.Equal(result))
}

func TestExtractProduceRespV9(t *testing.T) {
	input := []byte(
		"\x02\x12\x71\x75\x69\x63\x6b\x73\x74\x61\x72\x74\x2d\x65\x76\x65\x6e\x74\x73\x02\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00")
	partition := ProduceRespPartition{
		Index:           0,
		ErrorCode:       0,
		BaseOffset:      0,
		LogAppendTimeMs: -1,
		LogStartOffset:  0,
		RecordErrors:    []RecordError{},
		ErrorMessage:    "",
	}
	topic := ProduceRespTopic{Name: "quickstart-events", Partitions: []ProduceRespPartition{partition}}
	expectedResult := ProduceResp{
		Topics:         []ProduceRespTopic{topic},
		ThrottleTimeMs: 0,
	}
	decoder := NewPacketDecoder(input)
	decoder.SetAPIInfo(KProduce, 9)
	result, err := decoder.ExtractProduceResp()
	assert.NoError(t, err)
	assert.True(t, expectedResult.Equal(result))
}
