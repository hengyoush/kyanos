package common

import (
	"encoding/json"
)

type FetchReqPartition struct {
	Index              int32 `json:"index"`
	CurrentLeaderEpoch int32 `json:"current_leader_epoch"`
	FetchOffset        int64 `json:"fetch_offset"`
	LastFetchedEpoch   int32 `json:"last_fetched_epoch"`
	LogStartOffset     int64 `json:"log_start_offset"`
	PartitionMaxBytes  int32 `json:"partition_max_bytes"`
}

func (p FetchReqPartition) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

type FetchReqTopic struct {
	Name       string              `json:"name"`
	Partitions []FetchReqPartition `json:"partitions"`
}

func (p FetchReqTopic) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

type FetchForgottenTopicsData struct {
	Name             string  `json:"name"`
	PartitionIndices []int32 `json:"partition_indices"`
}

func (p FetchForgottenTopicsData) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

type FetchReq struct {
	ReplicaID       int32                      `json:"replica_id"`
	SessionID       int32                      `json:"session_id"`
	SessionEpoch    int32                      `json:"session_epoch"`
	Topics          []FetchReqTopic            `json:"topics"`
	ForgottenTopics []FetchForgottenTopicsData `json:"forgotten_topics"`
	RackID          string                     `json:"rack_id"`
}

func (p FetchReq) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

type FetchRespAbortedTransaction struct {
	ProducerID  int64 `json:"producer_id"`
	FirstOffset int64 `json:"first_offset"`
}

func (p FetchRespAbortedTransaction) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

type FetchRespPartition struct {
	Index                int32                         `json:"index"`
	ErrorCode            int16                         `json:"error_code"`
	HighWatermark        int64                         `json:"high_watermark"`
	LastStableOffset     int64                         `json:"last_stable_offset"`
	LogStartOffset       int64                         `json:"log_start_offset"`
	AbortedTransactions  []FetchRespAbortedTransaction `json:"aborted_transactions"`
	PreferredReadReplica int32                         `json:"preferred_read_replica"`
	MessageSet           MessageSet                    `json:"message_set"`
}

func (p FetchRespPartition) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

type FetchRespTopic struct {
	Name       string               `json:"name"`
	Partitions []FetchRespPartition `json:"partitions"`
}

func (p FetchRespTopic) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

type FetchResp struct {
	ThrottleTimeMs int32            `json:"throttle_time_ms"`
	ErrorCode      int16            `json:"error_code"`
	SessionID      int32            `json:"session_id"`
	Topics         []FetchRespTopic `json:"topics"`
}

func (p FetchResp) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

func (p FetchReqPartition) Equals(other FetchReqPartition) bool {
	return p.Index == other.Index &&
		p.CurrentLeaderEpoch == other.CurrentLeaderEpoch &&
		p.FetchOffset == other.FetchOffset &&
		p.LastFetchedEpoch == other.LastFetchedEpoch &&
		p.LogStartOffset == other.LogStartOffset &&
		p.PartitionMaxBytes == other.PartitionMaxBytes
}

func (p FetchReqTopic) Equals(other FetchReqTopic) bool {
	if p.Name != other.Name || len(p.Partitions) != len(other.Partitions) {
		return false
	}
	for i := range p.Partitions {
		if !p.Partitions[i].Equals(other.Partitions[i]) {
			return false
		}
	}
	return true
}

func (p FetchForgottenTopicsData) Equals(other FetchForgottenTopicsData) bool {
	if p.Name != other.Name || len(p.PartitionIndices) != len(other.PartitionIndices) {
		return false
	}
	for i := range p.PartitionIndices {
		if p.PartitionIndices[i] != other.PartitionIndices[i] {
			return false
		}
	}
	return true
}

func (p FetchReq) Equals(other FetchReq) bool {
	if p.ReplicaID != other.ReplicaID ||
		p.SessionID != other.SessionID ||
		len(p.Topics) != len(other.Topics) ||
		len(p.ForgottenTopics) != len(other.ForgottenTopics) {
		return false
	}
	for i := range p.Topics {
		if !p.Topics[i].Equals(other.Topics[i]) {
			return false
		}
	}
	for i := range p.ForgottenTopics {
		if !p.ForgottenTopics[i].Equals(other.ForgottenTopics[i]) {
			return false
		}
	}
	return true
}

func (p FetchRespAbortedTransaction) Equals(other FetchRespAbortedTransaction) bool {
	return p.ProducerID == other.ProducerID &&
		p.FirstOffset == other.FirstOffset
}

func (p FetchRespPartition) Equals(other FetchRespPartition) bool {
	if p.Index != other.Index ||
		p.ErrorCode != other.ErrorCode ||
		p.HighWatermark != other.HighWatermark ||
		p.LastStableOffset != other.LastStableOffset ||
		p.LogStartOffset != other.LogStartOffset ||
		p.PreferredReadReplica != other.PreferredReadReplica ||
		!p.MessageSet.Equals(other.MessageSet) ||
		len(p.AbortedTransactions) != len(other.AbortedTransactions) {
		return false
	}
	for i := range p.AbortedTransactions {
		if !p.AbortedTransactions[i].Equals(other.AbortedTransactions[i]) {
			return false
		}
	}
	return true
}

func (p FetchRespTopic) Equals(other FetchRespTopic) bool {
	if p.Name != other.Name || len(p.Partitions) != len(other.Partitions) {
		return false
	}
	for i := range p.Partitions {
		if !p.Partitions[i].Equals(other.Partitions[i]) {
			return false
		}
	}
	return true
}

func (p FetchResp) Equals(other FetchResp) bool {
	if p.ThrottleTimeMs != other.ThrottleTimeMs ||
		p.ErrorCode != other.ErrorCode ||
		p.SessionID != other.SessionID ||
		len(p.Topics) != len(other.Topics) {
		return false
	}
	for i := range p.Topics {
		if !p.Topics[i].Equals(other.Topics[i]) {
			return false
		}
	}
	return true
}
