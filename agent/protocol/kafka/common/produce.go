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

func (lhs ProduceReqPartition) Equal(rhs ProduceReqPartition) bool {
	return lhs.Index == rhs.Index && lhs.MessageSet.Equals(rhs.MessageSet)
}

func (lhs ProduceReqTopic) Equal(rhs ProduceReqTopic) bool {
	if lhs.Name != rhs.Name {
		return false
	}
	if len(lhs.Partitions) != len(rhs.Partitions) {
		return false
	}
	for i := range lhs.Partitions {
		if !lhs.Partitions[i].Equal(rhs.Partitions[i]) {
			return false
		}
	}
	return true
}

func (lhs ProduceReq) Equal(rhs ProduceReq) bool {
	if lhs.TransactionalID != rhs.TransactionalID {
		return false
	}
	if lhs.Acks != rhs.Acks {
		return false
	}
	if lhs.TimeoutMs != rhs.TimeoutMs {
		return false
	}
	if len(lhs.Topics) != len(rhs.Topics) {
		return false
	}
	for i := range lhs.Topics {
		if !lhs.Topics[i].Equal(rhs.Topics[i]) {
			return false
		}
	}
	return true
}

func (lhs RecordError) Equal(rhs RecordError) bool {
	return lhs.BatchIndex == rhs.BatchIndex && lhs.ErrorMessage == rhs.ErrorMessage
}

func (lhs ProduceRespPartition) Equal(rhs ProduceRespPartition) bool {
	if lhs.Index != rhs.Index {
		return false
	}
	if lhs.ErrorCode != rhs.ErrorCode {
		return false
	}
	if lhs.BaseOffset != rhs.BaseOffset {
		return false
	}
	if lhs.LogAppendTimeMs != rhs.LogAppendTimeMs {
		return false
	}
	if lhs.LogStartOffset != rhs.LogStartOffset {
		return false
	}
	if lhs.ErrorMessage != rhs.ErrorMessage {
		return false
	}
	if len(lhs.RecordErrors) != len(rhs.RecordErrors) {
		return false
	}
	for i := range lhs.RecordErrors {
		if !lhs.RecordErrors[i].Equal(rhs.RecordErrors[i]) {
			return false
		}
	}
	return true
}

func (lhs ProduceRespTopic) Equal(rhs ProduceRespTopic) bool {
	if lhs.Name != rhs.Name {
		return false
	}
	if len(lhs.Partitions) != len(rhs.Partitions) {
		return false
	}
	for i := range lhs.Partitions {
		if !lhs.Partitions[i].Equal(rhs.Partitions[i]) {
			return false
		}
	}
	return true
}

func (lhs ProduceResp) Equal(rhs ProduceResp) bool {
	if lhs.ThrottleTimeMs != rhs.ThrottleTimeMs {
		return false
	}
	if len(lhs.Topics) != len(rhs.Topics) {
		return false
	}
	for i := range lhs.Topics {
		if !lhs.Topics[i].Equal(rhs.Topics[i]) {
			return false
		}
	}
	return true
}
