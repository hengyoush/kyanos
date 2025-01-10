package decoder

import (
	. "kyanos/agent/protocol/kafka/common"
)

func (pd *PacketDecoder) ExtractMetadataReqTopic() (MetadataReqTopic, error) {
	var r MetadataReqTopic
	var err error

	if pd.apiVersion >= 10 {
		r.TopicID, err = pd.ExtractString()
		if err != nil {
			return r, err
		}
	}

	if pd.apiVersion <= 9 {
		r.Name, err = pd.ExtractString()
		if err != nil {
			return r, err
		}
	} else {
		r.Name, err = pd.ExtractNullableString()
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

func (pd *PacketDecoder) ExtractMetadataReq() (MetadataReq, error) {
	var r MetadataReq
	var err error

	r.Topics, err = ExtractArray(pd.ExtractMetadataReqTopic, pd)
	if err != nil {
		return r, err
	}

	if pd.apiVersion >= 4 {
		r.AllowAutoTopicCreation, err = pd.ExtractBool()
		if err != nil {
			return r, err
		}
	}

	if pd.apiVersion >= 8 {
		r.IncludeClusterAuthorizedOperations, err = pd.ExtractBool()
		if err != nil {
			return r, err
		}
		r.IncludeTopicAuthorizedOperations, err = pd.ExtractBool()
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
