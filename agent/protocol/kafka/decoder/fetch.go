package decoder

import (
	. "kyanos/agent/protocol/kafka/common"
)

func (pd *PacketDecoder) ExtractFetchReqPartition() (FetchReqPartition, error) {
	var r FetchReqPartition
	var err error
	r.Index, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	if pd.apiVersion >= 9 {
		r.CurrentLeaderEpoch, err = pd.ExtractInt32()
		if err != nil {
			return r, err
		}
	} else {
		r.CurrentLeaderEpoch = -1
	}
	r.FetchOffset, err = pd.ExtractInt64()
	if err != nil {
		return r, err
	}
	if pd.apiVersion >= 12 {
		r.LastFetchedEpoch, err = pd.ExtractInt32()
		if err != nil {
			return r, err
		}
	} else {
		r.LastFetchedEpoch = -1
	}
	if pd.apiVersion >= 5 {
		r.LogStartOffset, err = pd.ExtractInt64()
		if err != nil {
			return r, err
		}
	} else {
		r.LogStartOffset = -1
	}
	r.PartitionMaxBytes, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	err = pd.ExtractTagSection()
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractFetchReqTopic() (FetchReqTopic, error) {
	var r FetchReqTopic
	var err error
	r.Name, err = pd.ExtractString()
	if err != nil {
		return r, err
	}
	r.Partitions, err = ExtractArray(pd.ExtractFetchReqPartition, pd)
	if err != nil {
		return r, err
	}
	err = pd.ExtractTagSection()
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractFetchForgottenTopicsData() (FetchForgottenTopicsData, error) {
	var r FetchForgottenTopicsData
	var err error
	r.Name, err = pd.ExtractString()
	if err != nil {
		return r, err
	}
	r.PartitionIndices, err = ExtractArray(pd.ExtractInt32, pd)
	if err != nil {
		return r, err
	}
	err = pd.ExtractTagSection()
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractFetchReq() (FetchReq, error) {
	var r FetchReq
	var err error
	r.ReplicaID, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	_, err = pd.ExtractInt32() // max_wait_ms
	if err != nil {
		return r, err
	}
	_, err = pd.ExtractInt32() // min_bytes
	if err != nil {
		return r, err
	}
	if pd.apiVersion >= 3 {
		_, err = pd.ExtractInt32() // max_bytes
		if err != nil {
			return r, err
		}
	}
	if pd.apiVersion >= 4 {
		_, err = pd.ExtractInt8() // isolation_level
		if err != nil {
			return r, err
		}
	}
	if pd.apiVersion >= 7 {
		r.SessionID, err = pd.ExtractInt32()
		if err != nil {
			return r, err
		}
		r.SessionEpoch, err = pd.ExtractInt32()
		if err != nil {
			return r, err
		}
	}
	r.Topics, err = ExtractArray(pd.ExtractFetchReqTopic, pd)
	if err != nil {
		return r, err
	}
	if pd.apiVersion >= 7 {
		r.ForgottenTopics, err = ExtractArray(pd.ExtractFetchForgottenTopicsData, pd)
		if err != nil {
			return r, err
		}
	}
	if pd.apiVersion >= 11 {
		r.RackID, err = pd.ExtractString()
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

func (pd *PacketDecoder) ExtractFetchRespAbortedTransaction() (FetchRespAbortedTransaction, error) {
	var r FetchRespAbortedTransaction
	var err error
	r.ProducerID, err = pd.ExtractInt64()
	if err != nil {
		return r, err
	}
	r.FirstOffset, err = pd.ExtractInt64()
	if err != nil {
		return r, err
	}
	err = pd.ExtractTagSection()
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractFetchRespPartition() (FetchRespPartition, error) {
	var r FetchRespPartition = FetchRespPartition{
		LastStableOffset:     -1,
		LogStartOffset:       -1,
		PreferredReadReplica: -1,
	}
	var err error
	r.Index, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	r.ErrorCode, err = pd.ExtractInt16()
	if err != nil {
		return r, err
	}
	r.HighWatermark, err = pd.ExtractInt64()
	if err != nil {
		return r, err
	}
	if pd.apiVersion >= 4 {
		r.LastStableOffset, err = pd.ExtractInt64()
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
	if pd.apiVersion >= 4 {
		r.AbortedTransactions, err = ExtractArray(pd.ExtractFetchRespAbortedTransaction, pd)
		if err != nil {
			return r, err
		}
	}
	if pd.apiVersion >= 11 {
		r.PreferredReadReplica, err = pd.ExtractInt32()
		if err != nil {
			return r, err
		}
	}
	r.MessageSet, err = pd.ExtractMessageSet()
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractFetchRespTopic() (FetchRespTopic, error) {
	var r FetchRespTopic
	var err error
	r.Name, err = pd.ExtractString()
	if err != nil {
		return r, err
	}
	r.Partitions, err = ExtractArray(pd.ExtractFetchRespPartition, pd)
	if err != nil {
		return r, err
	}
	err = pd.ExtractTagSection()
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractFetchResp() (FetchResp, error) {
	var r FetchResp
	var err error
	if pd.apiVersion >= 1 {
		r.ThrottleTimeMs, err = pd.ExtractInt32()
		if err != nil {
			return r, err
		}
	}
	if pd.apiVersion >= 7 {
		r.ErrorCode, err = pd.ExtractInt16()
		if err != nil {
			return r, err
		}
		r.SessionID, err = pd.ExtractInt32()
		if err != nil {
			return r, err
		}
	}
	r.Topics, err = ExtractArray(pd.ExtractFetchRespTopic, pd)
	if err != nil {
		return r, err
	}
	err = pd.ExtractTagSection()
	if err != nil {
		return r, err
	}
	return r, nil
}
