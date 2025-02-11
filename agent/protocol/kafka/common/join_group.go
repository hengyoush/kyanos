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

func (lhs JoinGroupProtocol) Equal(rhs JoinGroupProtocol) bool {
	return lhs.Protocol == rhs.Protocol
}

func (lhs JoinGroupMember) Equal(rhs JoinGroupMember) bool {
	if lhs.MemberID != rhs.MemberID {
		return false
	}
	return lhs.GroupInstanceID == rhs.GroupInstanceID
}

func (lhs JoinGroupReq) Equal(rhs JoinGroupReq) bool {
	if lhs.GroupID != rhs.GroupID {
		return false
	}
	if lhs.SessionTimeoutMs != rhs.SessionTimeoutMs {
		return false
	}
	if lhs.RebalanceTimeoutMs != rhs.RebalanceTimeoutMs {
		return false
	}
	if lhs.MemberID != rhs.MemberID {
		return false
	}
	if lhs.GroupInstanceID != rhs.GroupInstanceID {
		return false
	}
	if lhs.ProtocolType != rhs.ProtocolType {
		return false
	}
	if len(lhs.Protocols) != len(rhs.Protocols) {
		return false
	}
	for i := range lhs.Protocols {
		if !lhs.Protocols[i].Equal(rhs.Protocols[i]) {
			return false
		}
	}
	return true
}

func (lhs JoinGroupResp) Equal(rhs JoinGroupResp) bool {
	if lhs.ThrottleTimeMs != rhs.ThrottleTimeMs {
		return false
	}
	if lhs.ErrorCode != rhs.ErrorCode {
		return false
	}
	if lhs.GenerationID != rhs.GenerationID {
		return false
	}
	if lhs.ProtocolType != rhs.ProtocolType {
		return false
	}
	if lhs.ProtocolName != rhs.ProtocolName {
		return false
	}
	if lhs.Leader != rhs.Leader {
		return false
	}
	if lhs.MemberID != rhs.MemberID {
		return false
	}
	if len(lhs.Members) != len(rhs.Members) {
		return false
	}
	for i := range lhs.Members {
		if !lhs.Members[i].Equal(rhs.Members[i]) {
			return false
		}
	}
	return true
}
