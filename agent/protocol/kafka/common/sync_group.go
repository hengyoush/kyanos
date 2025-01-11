package common

import (
	"encoding/json"
)

type SyncGroupAssignment struct {
	MemberID string `json:"member_id"`
}

func (s SyncGroupAssignment) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

type SyncGroupReq struct {
	GroupID         string                `json:"group_id"`
	GenerationID    int32                 `json:"generation_id"`
	MemberID        string                `json:"member_id"`
	GroupInstanceID string                `json:"group_instance_id"`
	ProtocolType    string                `json:"protocol_type"`
	ProtocolName    string                `json:"protocol_name"`
	Assignments     []SyncGroupAssignment `json:"assignments"`
}

func (s SyncGroupReq) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

type SyncGroupResp struct {
	ThrottleTimeMs int32  `json:"throttle_time_ms"`
	ErrorCode      int16  `json:"error_code"`
	ProtocolType   string `json:"protocol_type"`
	ProtocolName   string `json:"protocol_name"`
}

func (s SyncGroupResp) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

func (lhs SyncGroupAssignment) Equal(rhs SyncGroupAssignment) bool {
	return lhs.MemberID == rhs.MemberID
}

func (lhs SyncGroupReq) Equal(rhs SyncGroupReq) bool {
	if lhs.GroupID != rhs.GroupID {
		return false
	}
	if lhs.GenerationID != rhs.GenerationID {
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
	if lhs.ProtocolName != rhs.ProtocolName {
		return false
	}
	if len(lhs.Assignments) != len(rhs.Assignments) {
		return false
	}
	for i := range lhs.Assignments {
		if !lhs.Assignments[i].Equal(rhs.Assignments[i]) {
			return false
		}
	}
	return true
}

func (lhs SyncGroupResp) Equal(rhs SyncGroupResp) bool {
	if lhs.ThrottleTimeMs != rhs.ThrottleTimeMs {
		return false
	}
	if lhs.ErrorCode != rhs.ErrorCode {
		return false
	}
	if lhs.ProtocolType != rhs.ProtocolType {
		return false
	}
	return lhs.ProtocolName == rhs.ProtocolName
}
