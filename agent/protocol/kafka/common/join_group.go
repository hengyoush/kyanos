package common

import (
	"encoding/json"
)

type JoinGroupMember struct {
	MemberID        string `json:"member_id"`
	GroupInstanceID string `json:"group_instance_id"`
}

func (j JoinGroupMember) ToJSON() ([]byte, error) {
	return json.Marshal(j)
}

type JoinGroupProtocol struct {
	Protocol string `json:"protocol"`
}

func (j JoinGroupProtocol) ToJSON() ([]byte, error) {
	return json.Marshal(j)
}

type JoinGroupReq struct {
	GroupID            string              `json:"group_id"`
	SessionTimeoutMs   int32               `json:"session_timeout_ms"`
	RebalanceTimeoutMs int32               `json:"rebalance_timeout_ms"`
	MemberID           string              `json:"member_id"`
	GroupInstanceID    string              `json:"group_instance_id"`
	ProtocolType       string              `json:"protocol_type"`
	Protocols          []JoinGroupProtocol `json:"protocols"`
}

func (j JoinGroupReq) ToJSON() ([]byte, error) {
	return json.Marshal(j)
}

type JoinGroupResp struct {
	ThrottleTimeMs int32             `json:"throttle_time_ms"`
	ErrorCode      int16             `json:"error_code"`
	GenerationID   int32             `json:"generation_id"`
	ProtocolType   string            `json:"protocol_type"`
	ProtocolName   string            `json:"protocol_name"`
	Leader         string            `json:"leader"`
	MemberID       string            `json:"member_id"`
	Members        []JoinGroupMember `json:"members"`
}

func (j JoinGroupResp) ToJSON() ([]byte, error) {
	return json.Marshal(j)
}
