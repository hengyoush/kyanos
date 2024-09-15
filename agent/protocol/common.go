package protocol

import (
	"kyanos/agent/buffer"
)

func matchByTimestamp(reqStream *[]ParsedMessage, respStream *[]ParsedMessage) []Record {
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

func CreateFrameBase(streamBuffer *buffer.StreamBuffer, readBytes int) (FrameBase, bool) {
	seq := streamBuffer.Head().LeftBoundary()
	ts, ok := streamBuffer.FindTimestampBySeq(seq)
	if !ok {
		return FrameBase{}, false
	}
	return NewFrameBase(ts, readBytes, seq), true
}
