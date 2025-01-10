package decoder

import (
	. "kyanos/agent/protocol/kafka/common"
)

func (pd *PacketDecoder) ExtractSyncGroupAssignment() (SyncGroupAssignment, error) {
	var r SyncGroupAssignment
	var err error
	r.MemberID, err = pd.ExtractString()
	if err != nil {
		return r, err
	}
	_, err = pd.ExtractBytes()
	if err != nil {
		return r, err
	}
	err = pd.ExtractTagSection()
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractSyncGroupReq() (SyncGroupReq, error) {
	var r SyncGroupReq
	var err error
	r.GroupID, err = pd.ExtractString()
	if err != nil {
		return r, err
	}
	r.GenerationID, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	r.MemberID, err = pd.ExtractString()
	if err != nil {
		return r, err
	}
	if pd.apiVersion >= 3 {
		r.GroupInstanceID, err = pd.ExtractNullableString()
		if err != nil {
			return r, err
		}
	}
	if pd.apiVersion >= 5 {
		r.ProtocolType, err = pd.ExtractNullableString()
		if err != nil {
			return r, err
		}
		r.ProtocolName, err = pd.ExtractNullableString()
		if err != nil {
			return r, err
		}
	}
	r.Assignments, err = ExtractArray(pd.ExtractSyncGroupAssignment, pd)
	if err != nil {
		return r, err
	}
	err = pd.ExtractTagSection()
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractSyncGroupResp() (SyncGroupResp, error) {
	var r SyncGroupResp
	var err error
	if pd.apiVersion >= 1 {
		r.ThrottleTimeMs, err = pd.ExtractInt32()
		if err != nil {
			return r, err
		}
	}
	r.ErrorCode, err = pd.ExtractInt16()
	if err != nil {
		return r, err
	}
	if pd.apiVersion >= 5 {
		r.ProtocolType, err = pd.ExtractString()
		if err != nil {
			return r, err
		}
		r.ProtocolName, err = pd.ExtractString()
		if err != nil {
			return r, err
		}
	}
	_, err = pd.ExtractBytes()
	if err != nil {
		return r, err
	}
	err = pd.ExtractTagSection()
	if err != nil {
		return r, err
	}
	return r, nil
}
