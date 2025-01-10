package common

import (
	"encoding/json"
)

type RecordMessage struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (r RecordMessage) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

type RecordBatch struct {
	Records []RecordMessage `json:"records"`
}

func (r RecordBatch) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

type MessageSet struct {
	Size          int64         `json:"size"`
	RecordBatches []RecordBatch `json:"record_batches"`
}

func (m MessageSet) ToJSON(omitRecordBatches bool) ([]byte, error) {
	if omitRecordBatches {
		return json.Marshal(struct {
			Size int64 `json:"size"`
		}{
			Size: m.Size,
		})
	}
	return json.Marshal(m)
}

func (lhs RecordMessage) Equals(rhs RecordMessage) bool {
	return lhs.Key == rhs.Key && lhs.Value == rhs.Value
}

func (lhs RecordBatch) Equals(rhs RecordBatch) bool {
	if len(lhs.Records) != len(rhs.Records) {
		return false
	}
	for i := range lhs.Records {
		if !lhs.Records[i].Equals(rhs.Records[i]) {
			return false
		}
	}
	return true
}

func (lhs MessageSet) Equals(rhs MessageSet) bool {
	if len(lhs.RecordBatches) != len(rhs.RecordBatches) {
		return false
	}
	for i := range lhs.RecordBatches {
		if !lhs.RecordBatches[i].Equals(rhs.RecordBatches[i]) {
			return false
		}
	}
	return true
}
