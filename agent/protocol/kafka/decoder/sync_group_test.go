package decoder_test

import (
	"testing"

	. "kyanos/agent/protocol/kafka/common"
	. "kyanos/agent/protocol/kafka/decoder"

	"github.com/stretchr/testify/assert"
)

func TestExtractSyncGroupReq(t *testing.T) {
	input := []byte(
		"\x16\x63\x6f\x6e\x73\x6f\x6c\x65\x2d\x63\x6f\x6e\x73\x75\x6d\x65\x72\x2d\x33\x35\x34\x30\x00" +
			"\x00\x00\x01\x46\x63\x6f\x6e\x73\x75\x6d\x65\x72\x2d\x63\x6f\x6e\x73\x6f\x6c\x65\x2d\x63\x6f" +
			"\x6e\x73\x75\x6d\x65\x72\x2d\x33\x35\x34\x30\x2d\x31\x2d\x36\x35\x65\x38\x65\x32\x64\x61\x2d" +
			"\x66\x65\x38\x38\x2d\x34\x64\x63\x61\x2d\x39\x30\x65\x33\x2d\x30\x62\x37\x30\x63\x39\x61\x62" +
			"\x61\x37\x31\x61\x00\x09\x63\x6f\x6e\x73\x75\x6d\x65\x72\x06\x72\x61\x6e\x67\x65\x02\x46\x63" +
			"\x6f\x6e\x73\x75\x6d\x65\x72\x2d\x63\x6f\x6e\x73\x6f\x6c\x65\x2d\x63\x6f\x6e\x73\x75\x6d\x65" +
			"\x72\x2d\x33\x35\x34\x30\x2d\x31\x2d\x36\x35\x65\x38\x65\x32\x64\x61\x2d\x66\x65\x38\x38\x2d" +
			"\x34\x64\x63\x61\x2d\x39\x30\x65\x33\x2d\x30\x62\x37\x30\x63\x39\x61\x62\x61\x37\x31\x61\x26" +
			"\x00\x01\x00\x00\x00\x01\x00\x11\x71\x75\x69\x63\x6b\x73\x74\x61\x72\x74\x2d\x65\x76\x65\x6e" +
			"\x74\x73\x00\x00\x00\x01\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00")
	expectedResult := SyncGroupReq{
		GroupID:         "console-consumer-3540",
		GenerationID:    1,
		MemberID:        "consumer-console-consumer-3540-1-65e8e2da-fe88-4dca-90e3-0b70c9aba71a",
		GroupInstanceID: "",
		ProtocolType:    "consumer",
		ProtocolName:    "range",
		Assignments: []SyncGroupAssignment{
			{MemberID: "consumer-console-consumer-3540-1-65e8e2da-fe88-4dca-90e3-0b70c9aba71a"},
		},
	}
	decoder := NewPacketDecoder(input)
	decoder.SetAPIInfo(KSyncGroup, 5)
	result, err := decoder.ExtractSyncGroupReq()
	assert.NoError(t, err)
	assert.True(t, expectedResult.Equal(result))
	assert.Equal(t, expectedResult, result)
}

func TestExtractSyncGroupResp(t *testing.T) {
	input := []byte(
		"\x00\x00\x00\x00\x00\x00\x09\x63\x6f\x6e\x73\x75\x6d\x65\x72\x06\x72\x61\x6e\x67\x65\x26\x00" +
			"\x01\x00\x00\x00\x01\x00\x11\x71\x75\x69\x63\x6b\x73\x74\x61\x72\x74\x2d\x65\x76\x65\x6e\x74" +
			"\x73\x00\x00\x00\x01\x00\x00\x00\x00\xff\xff\xff\xff\x00")
	expectedResult := SyncGroupResp{
		ThrottleTimeMs: 0,
		ErrorCode:      0,
		ProtocolType:   "consumer",
		ProtocolName:   "range",
	}
	decoder := NewPacketDecoder(input)
	decoder.SetAPIInfo(KSyncGroup, 5)
	result, err := decoder.ExtractSyncGroupResp()
	assert.NoError(t, err)
	assert.True(t, expectedResult.Equal(result))
	assert.Equal(t, expectedResult, result)
}