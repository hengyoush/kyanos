package common

import (
	"encoding/json"
)

type ProduceReqPartition struct {
	Index      int32      `json:"index"`
	MessageSet MessageSet `json:"message_set"`
}

func (p ProduceReqPartition) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

type ProduceReqTopic struct {
	Name       string                `json:"name"`
	Partitions []ProduceReqPartition `json:"partitions"`
}

func (p ProduceReqTopic) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

type ProduceReq struct {
	TransactionalID string            `json:"transactional_id"`
	Acks            int16             `json:"acks"`
	TimeoutMs       int32             `json:"timeout_ms"`
	Topics          []ProduceReqTopic `json:"topics"`
}

func (p ProduceReq) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

type RecordError struct {
	BatchIndex   int32  `json:"batch_index"`
	ErrorMessage string `json:"error_message"`
}

func (r RecordError) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

type ProduceRespPartition struct {
	Index           int32         `json:"index"`
	ErrorCode       int16         `json:"error_code"`
	BaseOffset      int64         `json:"base_offset"`
	LogAppendTimeMs int64         `json:"log_append_time_ms"`
	LogStartOffset  int64         `json:"log_start_offset"`
	RecordErrors    []RecordError `json:"record_errors"`
	ErrorMessage    string        `json:"error_message"`
}

func (p ProduceRespPartition) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

type ProduceRespTopic struct {
	Name       string                 `json:"name"`
	Partitions []ProduceRespPartition `json:"partitions"`
}

func (p ProduceRespTopic) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

type ProduceResp struct {
	Topics         []ProduceRespTopic `json:"topics"`
	ThrottleTimeMs int32              `json:"throttle_time_ms"`
}

func (p ProduceResp) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}
