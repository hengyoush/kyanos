package protocol

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRedisMessage(seq uint64, timestamp uint64, byteSize int, isReq bool) *RedisMessage {
	return &RedisMessage{
		FrameBase: NewFrameBase(timestamp, byteSize, seq),
		payload:   fmt.Sprintf("payload-%d", seq),
		command:   "GET",
		isReq:     isReq,
	}
}

func TestRedisMatchTrimsPendingRequestsWithoutResponses(t *testing.T) {
	reqQueue := ParsedMessageQueue{}
	for i := 0; i < maxPendingParsedMessages+128; i++ {
		reqQueue = append(reqQueue, newTestRedisMessage(uint64(i+1), uint64(i+1), 64, true))
	}

	parser := RedisStreamParser{}
	reqStreams := map[StreamId]*ParsedMessageQueue{0: &reqQueue}

	records := parser.Match(reqStreams, map[StreamId]*ParsedMessageQueue{})

	require.Empty(t, records)
	require.Contains(t, reqStreams, StreamId(0))
	assert.Len(t, *reqStreams[0], maxPendingParsedMessages)
	assert.Equal(t, uint64(129), (*reqStreams[0])[0].Seq())
}

func TestRedisMatchTrimsPendingResponsesWithoutRequests(t *testing.T) {
	respQueue := ParsedMessageQueue{}
	for i := 0; i < maxPendingParsedMessages+64; i++ {
		respQueue = append(respQueue, newTestRedisMessage(uint64(i+1), uint64(i+1), 64, false))
	}

	parser := RedisStreamParser{}
	respStreams := map[StreamId]*ParsedMessageQueue{0: &respQueue}

	records := parser.Match(map[StreamId]*ParsedMessageQueue{}, respStreams)

	require.Empty(t, records)
	require.Contains(t, respStreams, StreamId(0))
	assert.Len(t, *respStreams[0], maxPendingParsedMessages)
	assert.Equal(t, uint64(65), (*respStreams[0])[0].Seq())
}

func TestRedisMatchRemovesEmptyQueuesAfterSuccessfulMatch(t *testing.T) {
	reqQueue := ParsedMessageQueue{
		newTestRedisMessage(1, 100, 16, true),
	}
	respQueue := ParsedMessageQueue{
		newTestRedisMessage(2, 200, 16, false),
	}

	parser := RedisStreamParser{}
	reqStreams := map[StreamId]*ParsedMessageQueue{0: &reqQueue}
	respStreams := map[StreamId]*ParsedMessageQueue{0: &respQueue}

	records := parser.Match(reqStreams, respStreams)

	require.Len(t, records, 1)
	assert.NotContains(t, reqStreams, StreamId(0))
	assert.NotContains(t, respStreams, StreamId(0))
}
