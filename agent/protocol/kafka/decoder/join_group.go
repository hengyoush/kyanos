package decoder

import (
	. "kyanos/agent/protocol/kafka/common"
)

func (pd *PacketDecoder) ExtractJoinGroupProtocol() (JoinGroupProtocol, error) {
	var r JoinGroupProtocol
	var err error
	r.Protocol, err = pd.ExtractString()
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

func (pd *PacketDecoder) ExtractJoinGroupMember() (JoinGroupMember, error) {
	var r JoinGroupMember
	var err error
	r.MemberID, err = pd.ExtractString()
	if err != nil {
		return r, err
	}
	if pd.apiVersion >= 5 {
		r.GroupInstanceID, err = pd.ExtractNullableString()
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

func (pd *PacketDecoder) ExtractJoinGroupReq() (JoinGroupReq, error) {
	var r JoinGroupReq
	var err error
	r.GroupID, err = pd.ExtractString()
	if err != nil {
		return r, err
	}
	r.SessionTimeoutMs, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	if pd.apiVersion >= 1 {
		r.RebalanceTimeoutMs, err = pd.ExtractInt32()
		if err != nil {
			return r, err
		}
	}
	r.MemberID, err = pd.ExtractString()
	if err != nil {
		return r, err
	}
	if pd.apiVersion >= 5 {
		r.GroupInstanceID, err = pd.ExtractNullableString()
		if err != nil {
			return r, err
		}
	}
	r.ProtocolType, err = pd.ExtractString()
	if err != nil {
		return r, err
	}
	r.Protocols, err = ExtractArray(pd.ExtractJoinGroupProtocol, pd)
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractJoinGroupResp() (JoinGroupResp, error) {
	var r JoinGroupResp
	var err error
	if pd.apiVersion >= 2 {
		r.ThrottleTimeMs, err = pd.ExtractInt32()
		if err != nil {
			return r, err
		}
	}
	r.ErrorCode, err = pd.ExtractInt16()
	if err != nil {
		return r, err
	}
	r.GenerationID, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	if pd.apiVersion >= 7 {
		r.ProtocolType, err = pd.ExtractNullableString()
		if err != nil {
			return r, err
		}
		r.ProtocolName, err = pd.ExtractNullableString()
		if err != nil {
			return r, err
		}
	} else {
		r.ProtocolType, err = pd.ExtractString()
		if err != nil {
			return r, err
		}
		r.ProtocolName, err = pd.ExtractString()
		if err != nil {
			return r, err
		}
	}
	r.Leader, err = pd.ExtractString()
	if err != nil {
		return r, err
	}
	r.MemberID, err = pd.ExtractString()
	if err != nil {
		return r, err
	}
	r.Members, err = ExtractArray(pd.ExtractJoinGroupMember, pd)
	if err != nil {
		return r, err
	}
	return r, nil
}
