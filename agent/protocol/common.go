package protocol

import (
	"kyanos/agent/buffer"
)

const (
	maxPendingParsedMessages      = 1024
	maxPendingParsedMessagesBytes = 16 * 1024 * 1024
)

func matchByTimestamp(reqStream *ParsedMessageQueue, respStream *ParsedMessageQueue) []Record {
	if len(*reqStream) == 0 || len(*respStream) == 0 {
		return nil
	}

	record := Record{}
	records := make([]Record, 0)
	for len(*respStream) > 0 {
		var req ParsedMessage
		if len(*reqStream) == 0 {
			req = nil
		} else {
			req = (*reqStream)[0]
		}

		resp := (*respStream)[0]
		if req != nil && req.TimestampNs() < resp.TimestampNs() {
			record.Req = req
			*reqStream = (*reqStream)[1:]
		} else {
			if record.Req != nil {
				record.Resp = resp
				records = append(records, record)
				record = Record{}
			}

			*respStream = (*respStream)[1:]
		}
	}
	return records
}

func trimPendingParsedMessages(queue *ParsedMessageQueue, maxCount int, maxBytes int) {
	if queue == nil || len(*queue) == 0 {
		return
	}

	start := len(*queue)
	keptCount := 0
	keptBytes := 0
	for i := len(*queue) - 1; i >= 0; i-- {
		msgBytes := max(1, (*queue)[i].ByteSize())
		if keptCount > 0 && (keptCount+1 > maxCount || keptBytes+msgBytes > maxBytes) {
			break
		}
		start = i
		keptCount++
		keptBytes += msgBytes
	}

	if start > 0 {
		*queue = (*queue)[start:]
	}
}

func trimPendingParsedMessagesForStream(streams map[StreamId]*ParsedMessageQueue, streamID StreamId) {
	queue, ok := streams[streamID]
	if !ok || queue == nil {
		return
	}

	trimPendingParsedMessages(queue, maxPendingParsedMessages, maxPendingParsedMessagesBytes)
	if len(*queue) == 0 {
		delete(streams, streamID)
	}
}

func CreateFrameBase(streamBuffer *buffer.StreamBuffer, readBytes int) (FrameBase, bool) {
	seq := streamBuffer.Head().LeftBoundary()
	ts, ok := streamBuffer.FindTimestampBySeq(seq)
	if !ok {
		return FrameBase{}, false
	}
	return NewFrameBase(ts, readBytes, seq), true
}
