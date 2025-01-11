package decoder_test

import (
	"testing"

	. "kyanos/agent/protocol/kafka/common"
	"kyanos/agent/protocol/kafka/decoder"

	"github.com/stretchr/testify/assert"
)

func TestFetchReqPartitionEquality(t *testing.T) {
	lhs := FetchReqPartition{Index: 1, CurrentLeaderEpoch: 2, FetchOffset: 3, LastFetchedEpoch: 4, LogStartOffset: 5, PartitionMaxBytes: 6}
	rhs := FetchReqPartition{Index: 1, CurrentLeaderEpoch: 2, FetchOffset: 3, LastFetchedEpoch: 4, LogStartOffset: 5, PartitionMaxBytes: 6}
	assert.Equal(t, lhs, rhs)
}

func TestFetchReqTopicEquality(t *testing.T) {
	lhs := FetchReqTopic{Name: "topic1", Partitions: []FetchReqPartition{{Index: 1}}}
	rhs := FetchReqTopic{Name: "topic1", Partitions: []FetchReqPartition{{Index: 1}}}
	assert.Equal(t, lhs, rhs)
}

func TestFetchForgottenTopicsDataEquality(t *testing.T) {
	lhs := FetchForgottenTopicsData{Name: "topic1", PartitionIndices: []int32{1, 2, 3}}
	rhs := FetchForgottenTopicsData{Name: "topic1", PartitionIndices: []int32{1, 2, 3}}
	assert.Equal(t, lhs, rhs)
}

func TestFetchReqEquality(t *testing.T) {
	lhs := FetchReq{ReplicaID: 1, SessionID: 2, SessionEpoch: 3, Topics: []FetchReqTopic{{Name: "topic1"}}, ForgottenTopics: []FetchForgottenTopicsData{{Name: "topic2"}}, RackID: "rack1"}
	rhs := FetchReq{ReplicaID: 1, SessionID: 2, SessionEpoch: 3, Topics: []FetchReqTopic{{Name: "topic1"}}, ForgottenTopics: []FetchForgottenTopicsData{{Name: "topic2"}}, RackID: "rack1"}
	assert.Equal(t, lhs, rhs)
}

func TestFetchRespAbortedTransactionEquality(t *testing.T) {
	lhs := FetchRespAbortedTransaction{ProducerID: 1, FirstOffset: 2}
	rhs := FetchRespAbortedTransaction{ProducerID: 1, FirstOffset: 2}
	assert.Equal(t, lhs, rhs)
}

func TestFetchRespPartitionEquality(t *testing.T) {
	lhs := FetchRespPartition{Index: 1, ErrorCode: 2, HighWatermark: 3, LastStableOffset: 4, LogStartOffset: 5, PreferredReadReplica: 6, AbortedTransactions: []FetchRespAbortedTransaction{{ProducerID: 1}}, MessageSet: MessageSet{Size: 7}}
	rhs := FetchRespPartition{Index: 1, ErrorCode: 2, HighWatermark: 3, LastStableOffset: 4, LogStartOffset: 5, PreferredReadReplica: 6, AbortedTransactions: []FetchRespAbortedTransaction{{ProducerID: 1}}, MessageSet: MessageSet{Size: 7}}
	assert.Equal(t, lhs, rhs)
}

func TestFetchRespTopicEquality(t *testing.T) {
	lhs := FetchRespTopic{Name: "topic1", Partitions: []FetchRespPartition{{Index: 1}}}
	rhs := FetchRespTopic{Name: "topic1", Partitions: []FetchRespPartition{{Index: 1}}}
	assert.Equal(t, lhs, rhs)
}

func TestFetchRespEquality(t *testing.T) {
	lhs := FetchResp{ThrottleTimeMs: 1, ErrorCode: 2, SessionID: 3, Topics: []FetchRespTopic{{Name: "topic1"}}}
	rhs := FetchResp{ThrottleTimeMs: 1, ErrorCode: 2, SessionID: 3, Topics: []FetchRespTopic{{Name: "topic1"}}}
	assert.Equal(t, lhs, rhs)
}

func TestFetchReqEqual(t *testing.T) {
	req1 := FetchReq{
		ReplicaID:    1,
		SessionID:    1,
		SessionEpoch: 1,
		Topics: []FetchReqTopic{
			{
				Name: "topic1",
				Partitions: []FetchReqPartition{
					{Index: 1, CurrentLeaderEpoch: 1, FetchOffset: 1, LastFetchedEpoch: 1, LogStartOffset: 1, PartitionMaxBytes: 1},
				},
			},
		},
		ForgottenTopics: []FetchForgottenTopicsData{
			{Name: "topic1", PartitionIndices: []int32{1}},
		},
		RackID: "rack1",
	}

	req2 := FetchReq{
		ReplicaID:    1,
		SessionID:    1,
		SessionEpoch: 1,
		Topics: []FetchReqTopic{
			{
				Name: "topic1",
				Partitions: []FetchReqPartition{
					{Index: 1, CurrentLeaderEpoch: 1, FetchOffset: 1, LastFetchedEpoch: 1, LogStartOffset: 1, PartitionMaxBytes: 1},
				},
			},
		},
		ForgottenTopics: []FetchForgottenTopicsData{
			{Name: "topic1", PartitionIndices: []int32{1}},
		},
		RackID: "rack1",
	}

	assert.True(t, req1.Equals(req2))
}

func TestExtractFetchReqV4(t *testing.T) {
	input := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0xF4, 0x00, 0x00, 0x00, 0x01, 0x03, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x08, 0x6D, 0x79, 0x2D, 0x74, 0x6F, 0x70, 0x69, 0x63, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x7E, 0x00, 0x10, 0x00, 0x00,
	}

	expectedResult := FetchReq{
		ReplicaID:       -1,
		SessionID:       0,
		SessionEpoch:    -1,
		Topics:          []FetchReqTopic{{Name: "my-topic", Partitions: []FetchReqPartition{{Index: 0, CurrentLeaderEpoch: -1, FetchOffset: 382, LastFetchedEpoch: -1, PartitionMaxBytes: 1048576, LogStartOffset: -1}}}},
		ForgottenTopics: []FetchForgottenTopicsData{},
		RackID:          "",
	}

	decoder := decoder.NewPacketDecoder(input)
	decoder.SetAPIInfo(KFetch, 4)
	result, err := decoder.ExtractFetchReq()
	assert.NoError(t, err)
	assert.True(t, expectedResult.Equals(result))
}

func TestExtractFetchReqV11(t *testing.T) {
	input := []byte("\xff\xff\xff\xff\x00\x00\x01\xf4\x00\x00\x00\x01\x03\x20\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x01\x00\x11\x71\x75\x69\x63\x6b\x73\x74\x61\x72\x74\x2d\x65\x76\x65" +
		"\x6e\x74\x73\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00")

	expectedResult := FetchReq{
		ReplicaID:       -1,
		SessionID:       0,
		SessionEpoch:    0,
		Topics:          []FetchReqTopic{{Name: "quickstart-events", Partitions: []FetchReqPartition{{Index: 0, CurrentLeaderEpoch: 0, FetchOffset: 0, LogStartOffset: -1, PartitionMaxBytes: 1048576, LastFetchedEpoch: -1}}}},
		ForgottenTopics: []FetchForgottenTopicsData{},
		RackID:          "",
	}

	decoder := decoder.NewPacketDecoder(input)
	decoder.SetAPIInfo(KFetch, 11)
	result, err := decoder.ExtractFetchReq()
	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
}

func TestExtractFetchReqV12(t *testing.T) {
	input := []byte(
		"\xff\xff\xff\xff\x00\x00\x01\xf4\x00\x00\x00\x01\x03\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x02\x12\x71\x75\x69\x63\x6b\x73\x74\x61\x72\x74\x2d\x65\x76\x65\x6e\x74\x73\x02\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff" +
			"\xff\xff\xff\xff\x00\x10\x00\x00\x00\x00\x01\x01\x00")

	expectedResult := FetchReq{
		ReplicaID:       -1,
		SessionID:       0,
		SessionEpoch:    0,
		Topics:          []FetchReqTopic{{Name: "quickstart-events", Partitions: []FetchReqPartition{{Index: 0, CurrentLeaderEpoch: 0, FetchOffset: 0, LogStartOffset: -1, PartitionMaxBytes: 1048576, LastFetchedEpoch: -1}}}},
		ForgottenTopics: []FetchForgottenTopicsData{},
		RackID:          "",
	}

	decoder := decoder.NewPacketDecoder(input)
	decoder.SetAPIInfo(KFetch, 12)
	result, err := decoder.ExtractFetchReq()
	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
}

func TestExtractFetchRespV4(t *testing.T) {
	input := []byte("\x00\x00\x00\x00\x00\x00\x00\x01\x00\x08\x6D\x79\x2D\x74\x6F\x70\x69\x63\x00\x00\x00\x01" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x7E\x00\x00\x00\x00\x00\x00\x01\x7E\xFF" +
		"\xFF\xFF\xFF\x00\x00\x00\x00")

	messageSet := MessageSet{Size: 0, RecordBatches: []RecordBatch{}}
	partition := FetchRespPartition{
		Index:                0,
		ErrorCode:            0,
		HighWatermark:        382,
		LastStableOffset:     382,
		LogStartOffset:       -1,
		AbortedTransactions:  []FetchRespAbortedTransaction{},
		PreferredReadReplica: -1,
		MessageSet:           messageSet,
	}
	topic := FetchRespTopic{
		Name:       "my-topic",
		Partitions: []FetchRespPartition{partition},
	}
	expectedResult := FetchResp{
		ThrottleTimeMs: 0,
		ErrorCode:      0,
		SessionID:      0,
		Topics:         []FetchRespTopic{topic},
	}

	decoder := decoder.NewPacketDecoder(input)
	decoder.SetAPIInfo(KFetch, 4)
	result, err := decoder.ExtractFetchResp()
	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
}

func TestExtractFetchRespV11(t *testing.T) {
	input := []byte(
		"\x00\x00\x00\x00\x00\x00\x27\xd5\xb6\xd1\x00\x00\x00\x01\x00\x11\x71\x75\x69\x63\x6b\x73\x74" +
			"\x61\x72\x74\x2d\x65\x76\x65\x6e\x74\x73\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" +
			"\xff\xff\xff\xff\xff\xff\x00\x00\x01\x71\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x38\x00" +
			"\x00\x00\x00\x02\x7e\x35\x4f\xcb\x00\x00\x00\x00\x00\x00\x00\x00\x01\x7a\xb0\x95\x78\xbc\x00" +
			"\x00\x01\x7a\xb0\x95\x78\xbc\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00" +
			"\x00\x01\x0c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x38\x00\x00" +
			"\x00\x00\x02\x1b\x91\x32\x93\x00\x00\x00\x00\x00\x00\x00\x00\x01\x7a\xb2\x08\x48\x52\x00\x00" +
			"\x01\x7a\xb2\x08\x48\x52\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00" +
			"\x01\x0c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x38\x00\x00\x00" +
			"\x00\x02\x99\x41\x19\xe9\x00\x00\x00\x00\x00\x00\x00\x00\x01\x7a\xb2\x08\xde\x56\x00\x00\x01" +
			"\x7a\xb2\x08\xde\x56\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x01" +
			"\x0c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x46\x00\x00\x00\x00" +
			"\x02\xa7\x88\x71\xd8\x00\x00\x00\x00\x00\x00\x00\x00\x01\x7a\xb2\x0a\x70\x1d\x00\x00\x01\x7a" +
			"\xb2\x0a\x70\x1d\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x01\x28" +
			"\x00\x00\x00\x01\x1c\x4d\x79\x20\x66\x69\x72\x73\x74\x20\x65\x76\x65\x6e\x74\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x04\x00\x00\x00\x47\x00\x00\x00\x00\x02\x5c\x9d\xc5\x05\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x01\x7a\xb2\x0a\xb7\xe5\x00\x00\x01\x7a\xb2\x0a\xb7\xe5\xff\xff\xff\xff\xff\xff" +
			"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x01\x2a\x00\x00\x00\x01\x1e\x4d\x79\x20\x73\x65" +
			"\x63\x6f\x6e\x64\x20\x65\x76\x65\x6e\x74\x00")

	recordBatch1 := RecordBatch{Records: []RecordMessage{{Key: "", Value: ""}}}
	recordBatch2 := RecordBatch{Records: []RecordMessage{{Key: "", Value: ""}}}
	recordBatch3 := RecordBatch{Records: []RecordMessage{{Key: "", Value: ""}}}
	recordBatch4 := RecordBatch{Records: []RecordMessage{{Key: "", Value: "My first event"}}}
	recordBatch5 := RecordBatch{Records: []RecordMessage{{Key: "", Value: "My second event"}}}
	messageSet := MessageSet{
		Size:          369,
		RecordBatches: []RecordBatch{recordBatch1, recordBatch2, recordBatch3, recordBatch4, recordBatch5},
	}
	partition := FetchRespPartition{
		Index:                0,
		ErrorCode:            0,
		HighWatermark:        5,
		LastStableOffset:     5,
		LogStartOffset:       0,
		AbortedTransactions:  []FetchRespAbortedTransaction{},
		PreferredReadReplica: -1,
		MessageSet:           messageSet,
	}
	topic := FetchRespTopic{
		Name:       "quickstart-events",
		Partitions: []FetchRespPartition{partition},
	}
	expectedResult := FetchResp{
		ThrottleTimeMs: 0,
		ErrorCode:      0,
		SessionID:      668317393,
		Topics:         []FetchRespTopic{topic},
	}

	decoder := decoder.NewPacketDecoder(input)
	decoder.SetAPIInfo(KFetch, 11)
	result, err := decoder.ExtractFetchResp()
	assert.NoError(t, err)
	assert.True(t, expectedResult.Equals(result))
}

func TestExtractFetchRespV12(t *testing.T) {
	input := []byte(
		"\x00\x00\x00\x00\x00\x00\x27\xd5\xb6\xd1\x02\x12\x71\x75\x69\x63\x6b\x73\x74\x61\x72\x74\x2d" +
			"\x65\x76\x65\x6e\x74\x73\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00" +
			"\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\xff\xff\xff\xf2\x02\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x38\x00\x00\x00\x00\x02\x7e\x35\x4f\xcb\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x01\x7a\xb0\x95\x78\xbc\x00\x00\x01\x7a\xb0\x95\x78\xbc\xff\xff\xff\xff\xff" +
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x01\x0c\x00\x00\x00\x01\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x01\x00\x00\x00\x38\x00\x00\x00\x00\x02\x1b\x91\x32\x93\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x01\x7a\xb2\x08\x48\x52\x00\x00\x01\x7a\xb2\x08\x48\x52\xff\xff\xff\xff\xff\xff" +
			"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x01\x0c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x02\x00\x00\x00\x38\x00\x00\x00\x00\x02\x99\x41\x19\xe9\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x01\x7a\xb2\x08\xde\x56\x00\x00\x01\x7a\xb2\x08\xde\x56\xff\xff\xff\xff\xff\xff\xff" +
			"\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x01\x0c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x03\x00\x00\x00\x46\x00\x00\x00\x00\x02\xa7\x88\x71\xd8\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x01\x7a\xb2\x0a\x70\x1d\x00\x00\x01\x7a\xb2\x0a\x70\x1d\xff\xff\xff\xff\xff\xff\xff\xff" +
			"\xff\xff\xff\xff\xff\xff\x00\x00\x00\x01\x28\x00\x00\x00\x01\x1c\x4d\x79\x20\x66\x69\x72\x73" +
			"\x74\x20\x65\x76\x65\x6e\x74\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x47\x00\x00\x00" +
			"\x00\x02\x5c\x9d\xc5\x05\x00\x00\x00\x00\x00\x00\x00\x00\x01\x7a\xb2\x0a\xb7\xe5\x00\x00\x01" +
			"\x7a\xb2\x0a\xb7\xe5\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x01" +
			"\x2a\x00\x00\x00\x01\x1e\x4d\x79\x20\x73\x65\x63\x6f\x6e\x64\x20\x65\x76\x65\x6e\x74\x00\x00" +
			"\x00\x00")

	recordBatch1 := RecordBatch{Records: []RecordMessage{{Key: "", Value: ""}}}
	recordBatch2 := RecordBatch{Records: []RecordMessage{{Key: "", Value: ""}}}
	recordBatch3 := RecordBatch{Records: []RecordMessage{{Key: "", Value: ""}}}
	recordBatch4 := RecordBatch{Records: []RecordMessage{{Key: "", Value: "My first event"}}}
	recordBatch5 := RecordBatch{Records: []RecordMessage{{Key: "", Value: "My second event"}}}
	messageSet := MessageSet{
		Size:          369,
		RecordBatches: []RecordBatch{recordBatch1, recordBatch2, recordBatch3, recordBatch4, recordBatch5},
	}
	partition := FetchRespPartition{
		Index:                0,
		ErrorCode:            0,
		HighWatermark:        5,
		LastStableOffset:     5,
		LogStartOffset:       0,
		AbortedTransactions:  []FetchRespAbortedTransaction{},
		PreferredReadReplica: -1,
		MessageSet:           messageSet,
	}
	topic := FetchRespTopic{
		Name:       "quickstart-events",
		Partitions: []FetchRespPartition{partition},
	}
	expectedResult := FetchResp{
		ThrottleTimeMs: 0,
		ErrorCode:      0,
		SessionID:      668317393,
		Topics:         []FetchRespTopic{topic},
	}

	decoder := decoder.NewPacketDecoder(input)
	decoder.SetAPIInfo(KFetch, 12)
	result, err := decoder.ExtractFetchResp()
	assert.NoError(t, err)
	assert.True(t, expectedResult.Equals(result))
}

func TestExtractFetchRespV11MissingMessageSet(t *testing.T) {
	input :=
		"\x00\x00\x00\x00\x00\x00\x27\xd5\xb6\xd1\x00\x00\x00\x01\x00\x11\x71\x75\x69\x63\x6b\x73\x74" +
			"\x61\x72\x74\x2d\x65\x76\x65\x6e\x74\x73\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" +
			"\xff\xff\xff\xff\xff\xff\x00\x00\x01\x71\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

	messageSet := MessageSet{Size: 369, RecordBatches: []RecordBatch{}}
	partition := FetchRespPartition{
		Index:                0,
		ErrorCode:            0,
		HighWatermark:        5,
		LastStableOffset:     5,
		LogStartOffset:       0,
		AbortedTransactions:  []FetchRespAbortedTransaction{},
		PreferredReadReplica: -1,
		MessageSet:           messageSet,
	}
	topic := FetchRespTopic{
		Name:       "quickstart-events",
		Partitions: []FetchRespPartition{partition},
	}
	expectedResult := FetchResp{
		ThrottleTimeMs: 0,
		ErrorCode:      0,
		SessionID:      668317393,
		Topics:         []FetchRespTopic{topic},
	}

	decoder := decoder.NewPacketDecoder([]byte(input))
	decoder.SetAPIInfo(KFetch, 11)
	result, err := decoder.ExtractFetchResp()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assert.True(t, expectedResult.Equals(result))
}
func TestExtractFetchRespV12MissingMessageSet(t *testing.T) {
	input := []byte(("\x00\x00\x00\x00\x00\x00\x27\xd5\xb6\xd1\x02\x12\x71\x75\x69\x63\x6b\x73\x74\x61\x72\x74\x2d" +
		"\x65\x76\x65\x6e\x74\x73\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00" +
		"\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\xff\xff\xff\xf2\x02\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00"))
	messageSet := MessageSet{
		Size:          369,
		RecordBatches: []RecordBatch{},
	}
	partition := FetchRespPartition{
		Index:                0,
		ErrorCode:            0,
		HighWatermark:        5,
		LastStableOffset:     5,
		LogStartOffset:       0,
		AbortedTransactions:  []FetchRespAbortedTransaction{},
		PreferredReadReplica: -1,
		MessageSet:           messageSet,
	}
	topic := FetchRespTopic{
		Name:       "quickstart-events",
		Partitions: []FetchRespPartition{partition},
	}
	expectedResult := FetchResp{
		ThrottleTimeMs: 0,
		ErrorCode:      0,
		SessionID:      668317393,
		Topics:         []FetchRespTopic{topic},
	}

	decoder := decoder.NewPacketDecoder(input) // input is skipped as per the instruction
	decoder.SetAPIInfo(KFetch, 12)
	result, err := decoder.ExtractFetchResp()
	assert.NoError(t, err)
	assert.True(t, expectedResult.Equals(result))
}
