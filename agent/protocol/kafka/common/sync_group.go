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
