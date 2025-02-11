package decoder

import "kyanos/agent/protocol/kafka/common"

func (pd *PacketDecoder) ExtractProduceReqPartition() (common.ProduceReqPartition, error) {
	var r common.ProduceReqPartition
	var err error
	r.Index, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}

	r.MessageSet, err = pd.ExtractMessageSet()
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractProduceReqTopic() (common.ProduceReqTopic, error) {
	var r common.ProduceReqTopic
	var err error
	r.Name, err = pd.ExtractString()
	if err != nil {
		return r, err
	}
	r.Partitions, err = ExtractArray(pd.ExtractProduceReqPartition, pd)
	if err != nil {
		return r, err
	}
	err = pd.ExtractTagSection()
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractRecordError() (common.RecordError, error) {
	var r common.RecordError
	var err error
	r.BatchIndex, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	r.ErrorMessage, err = pd.ExtractNullableString()
	if err != nil {
		return r, err
	}
	err = pd.ExtractTagSection()
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractProduceRespPartition() (common.ProduceRespPartition, error) {
	var r common.ProduceRespPartition
	var err error
	r.Index, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	r.ErrorCode, err = pd.ExtractInt16()
	if err != nil {
		return r, err
	}
	r.BaseOffset, err = pd.ExtractInt64()
	if err != nil {
		return r, err
	}
	if pd.apiVersion >= 2 {
		r.LogAppendTimeMs, err = pd.ExtractInt64()
		if err != nil {
			return r, err
		}
	}
	if pd.apiVersion >= 5 {
		r.LogStartOffset, err = pd.ExtractInt64()
		if err != nil {
			return r, err
		}
	}
	if pd.apiVersion >= 8 {
		r.RecordErrors, err = ExtractArray(pd.ExtractRecordError, pd)
		if err != nil {
			return r, err
		}
		r.ErrorMessage, err = pd.ExtractNullableString()
		if err != nil {
			return r, err
		}
	}
	err = pd.ExtractTagSection()
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractProduceRespTopic() (common.ProduceRespTopic, error) {
	var r common.ProduceRespTopic
	var err error
	if pd.isFlexible {
		r.Name, err = pd.ExtractCompactString()
		if err != nil {
			return r, err
		}
		r.Partitions, err = ExtractCompactArray(pd.ExtractProduceRespPartition, pd)
		if err != nil {
			return r, err
		}
		err = pd.ExtractTagSection()
		if err != nil {
			return r, err
		}
	} else {
		r.Name, err = pd.ExtractString()
		if err != nil {
			return r, err
		}
		r.Partitions, err = ExtractArray(pd.ExtractProduceRespPartition, pd)
		if err != nil {
			return r, err
		}
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractProduceReq() (common.ProduceReq, error) {
	var r common.ProduceReq
	var err error
	if pd.isFlexible {
		r.TransactionalID, err = pd.ExtractCompactNullableString()
		if err != nil {
			return r, err
		}
	} else if pd.apiVersion >= 3 {
		r.TransactionalID, err = pd.ExtractNullableString()
		if err != nil {
			return r, err
		}
	}
	r.Acks, err = pd.ExtractInt16()
	if err != nil {
		return r, err
	}
	r.TimeoutMs, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	if pd.isFlexible {
		r.Topics, err = ExtractCompactArray(pd.ExtractProduceReqTopic, pd)
		if err != nil {
			return r, err
		}
	} else {
		r.Topics, err = ExtractArray(pd.ExtractProduceReqTopic, pd)
		if err != nil {
			return r, err
		}
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractProduceResp() (common.ProduceResp, error) {
	var r common.ProduceResp
	var err error
	if pd.isFlexible {
		r.Topics, err = ExtractCompactArray(pd.ExtractProduceRespTopic, pd)
		if err != nil {
			return r, err
		}
	} else {
		r.Topics, err = ExtractArray(pd.ExtractProduceRespTopic, pd)
		if err != nil {
			return r, err
		}
	}
	if pd.apiVersion >= 1 {
		r.ThrottleTimeMs, err = pd.ExtractInt32()
		if err != nil {
			return r, err
		}
	}
	if pd.isFlexible {
		err = pd.ExtractTagSection()
		if err != nil {
			return r, err
		}
	}
	return r, nil
}
