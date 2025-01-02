package common

import (
	"encoding/json"
	"kyanos/bpf"
	"kyanos/common"
	"time"
)

type annotatedRecordAlias struct {
	StartTime                  string               `json:"start_time"`
	EndTime                    string               `json:"end_time"`
	Protocol                   string               `json:"protocol"`
	Side                       string               `json:"side"`
	LocalAddr                  string               `json:"local_addr"`
	LocalPort                  uint16               `json:"local_port"`
	RemoteAddr                 string               `json:"remote_addr"`
	RemotePort                 uint16               `json:"remote_port"`
	Pid                        uint32               `json:"pid"`
	IsSsl                      bool                 `json:"is_ssl"`
	TotalDuration              float64              `json:"total_duration_ms"`
	BlackBoxDuration           float64              `json:"black_box_duration_ms"`
	ReadSocketDuration         float64              `json:"read_socket_duration_ms"`
	CopyToSocketBufferDuration float64              `json:"copy_to_socket_buffer_duration_ms"`
	ReqSize                    int                  `json:"req_size_bytes"`
	RespSize                   int                  `json:"resp_size_bytes"`
	ReqPlainTextSize           int                  `json:"req_plain_text_size_bytes"`
	RespPlainTextSize          int                  `json:"resp_plain_text_size_bytes"`
	Request                    string               `json:"request"`
	Response                   string               `json:"response"`
	ReqSyscallEventDetails     []SyscallEventDetail `json:"req_syscall_events"`
	RespSyscallEventDetails    []SyscallEventDetail `json:"resp_syscall_events"`
	ReqNicEventDetails         []NicEventDetail     `json:"req_nic_events"`
	RespNicEventDetails        []NicEventDetail     `json:"resp_nic_events"`
}

// MarshalJSON implements custom JSON marshaling for AnnotatedRecord
func (r *AnnotatedRecord) MarshalJSON() ([]byte, error) {
	return json.Marshal(&annotatedRecordAlias{
		StartTime:                  time.Unix(0, int64(r.StartTs)).Format(time.RFC3339Nano),
		EndTime:                    time.Unix(0, int64(r.EndTs)).Format(time.RFC3339Nano),
		Protocol:                   bpf.ProtocolNamesMap[bpf.AgentTrafficProtocolT(r.ConnDesc.Protocol)],
		Side:                       r.ConnDesc.Side.String(),
		LocalAddr:                  r.ConnDesc.LocalAddr.String(),
		LocalPort:                  uint16(r.ConnDesc.LocalPort),
		RemoteAddr:                 r.ConnDesc.RemoteAddr.String(),
		RemotePort:                 uint16(r.ConnDesc.RemotePort),
		Pid:                        r.ConnDesc.Pid,
		IsSsl:                      r.ConnDesc.IsSsl,
		TotalDuration:              r.GetTotalDurationMills(),
		BlackBoxDuration:           r.GetBlackBoxDurationMills(),
		ReadSocketDuration:         r.GetReadFromSocketBufferDurationMills(),
		CopyToSocketBufferDuration: common.NanoToMills(int32(r.CopyToSocketBufferDuration)),
		ReqSize:                    r.ReqSize,
		RespSize:                   r.RespSize,
		ReqPlainTextSize:           r.ReqPlainTextSize,
		RespPlainTextSize:          r.RespPlainTextSize,
		Request:                    r.Req.FormatToString(),
		Response:                   r.Resp.FormatToString(),
		ReqSyscallEventDetails:     r.ReqSyscallEventDetails,
		RespSyscallEventDetails:    r.RespSyscallEventDetails,
		ReqNicEventDetails:         r.ReqNicEventDetails,
		RespNicEventDetails:        r.RespNicEventDetails,
	})
}
