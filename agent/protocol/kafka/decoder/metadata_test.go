package decoder_test

import (
	"testing"

	. "kyanos/agent/protocol/kafka/common"
	. "kyanos/agent/protocol/kafka/decoder"

	"github.com/stretchr/testify/assert"
)

func TestExtractMetadataReqV5(t *testing.T) {
	input := []byte(
		"\x00\x00\x00\x01\x00\x10\x6b\x61" +
			"\x66\x6b\x61\x5f\x32\x2e\x31\x32\x2d\x31\x2e\x31\x2e\x31\x01")
	topic := MetadataReqTopic{TopicID: "", Name: "kafka_2.12-1.1.1"}
	expectedResult := MetadataReq{
		Topics:                 []MetadataReqTopic{topic},
		AllowAutoTopicCreation: true,
	}
	decoder := NewPacketDecoder(input)
	decoder.SetAPIInfo(KMetadata, 5)
	result, err := decoder.ExtractMetadataReq()
	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
}

func TestExtractMetadataReqV11(t *testing.T) {
	input := []byte(
		"\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x11\x6b\x61\x66\x6b\x61\x5f\x32\x2e\x31\x32\x2d\x32\x2e\x38" +
			"\x2e\x31\x00\x01\x00\x00")
	expectedResult := MetadataReq{
		Topics:                             []MetadataReqTopic{},
		AllowAutoTopicCreation:             true,
		IncludeClusterAuthorizedOperations: false,
		IncludeTopicAuthorizedOperations:   false,
	}
	decoder := NewPacketDecoder(input)
	decoder.SetAPIInfo(KMetadata, 11)
	result, err := decoder.ExtractMetadataReq()
	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
}
