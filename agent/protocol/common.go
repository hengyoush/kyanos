package protocol

import (
	"kyanos/common"

	"github.com/jefurry/logrus"
)

var log *logrus.Logger = common.Log

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
			record.req = req
			*reqStream = (*reqStream)[1:]
		} else {
			if record.req != nil {
				record.resp = resp
				records = append(records, record)
				record = Record{}
			}

			*respStream = (*respStream)[1:]
		}
	}
	return records
}
