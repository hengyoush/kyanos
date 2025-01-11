package decoder

import (
	"errors"
	"kyanos/agent/protocol/kafka/common"
)

func (pd *PacketDecoder) ExtractRecordMessage() (common.RecordMessage, error) {
	var r common.RecordMessage
	var err error
	length, err := pd.ExtractVarint()
	if err != nil {
		return r, err
	}
	err = pd.MarkOffset(length)
	if err != nil {
		return r, err
	}

	_, err = pd.ExtractInt8()
	if err != nil {
		return r, err
	}
	_, err = pd.ExtractVarlong()
	if err != nil {
		return r, err
	}
	_, err = pd.ExtractVarint()
	if err != nil {
		return r, err
	}
	r.Key, err = pd.ExtractBytesZigZag()
	if err != nil {
		return r, err
	}
	r.Value, err = pd.ExtractBytesZigZag()
	if err != nil {
		return r, err
	}

	err = pd.JumpToOffset()
	if err != nil {
		return r, err
	}
	return r, nil
}

func (pd *PacketDecoder) ExtractRecordBatch(offset *int32) (common.RecordBatch, error) {
	const kBaseOffsetLength = 8
	const kLengthLength = 4

	var r common.RecordBatch
	var err error
	_, err = pd.ExtractInt64()
	if err != nil {
		return r, err
	}

	length, err := pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	err = pd.MarkOffset(length)
	if err != nil {
		return r, err
	}

	_, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	magic, err := pd.ExtractInt8()
	if err != nil {
		return r, err
	}
	if magic < 2 {
		return r, errors.New("old record batch (message set) format not supported")
	}
	if magic > 2 {
		return r, errors.New("unknown magic in ExtractRecordBatch")
	}

	_, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	_, err = pd.ExtractInt16()
	if err != nil {
		return r, err
	}
	_, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}
	_, err = pd.ExtractInt64()
	if err != nil {
		return r, err
	}
	_, err = pd.ExtractInt64()
	if err != nil {
		return r, err
	}
	_, err = pd.ExtractInt64()
	if err != nil {
		return r, err
	}
	_, err = pd.ExtractInt16()
	if err != nil {
		return r, err
	}
	_, err = pd.ExtractInt32()
	if err != nil {
		return r, err
	}

	r.Records, err = ExtractRegularArray(pd.ExtractRecordMessage, pd)
	if err != nil {
		return r, err
	}
	err = pd.JumpToOffset()
	if err != nil {
		return r, err
	}

	*offset += length + kBaseOffsetLength + kLengthLength
	return r, nil
}

func (pd *PacketDecoder) ExtractMessageSet() (common.MessageSet, error) {
	var messageSet common.MessageSet = common.MessageSet{
		Size:          0,
		RecordBatches: []common.RecordBatch{},
	}
	var err error
	offset := int32(0)

	if pd.isFlexible {
		var size int32
		size, err = pd.ExtractUnsignedVarint()
		if err != nil {
			return messageSet, err
		}
		messageSet.Size = int64(size)
	} else {
		var size int32
		size, err = pd.ExtractInt32()
		if err != nil {
			return messageSet, err
		}
		messageSet.Size = int64(size)
	}
	if err != nil {
		return messageSet, err
	}
	err = pd.MarkOffset(int32(messageSet.Size))
	if err != nil {
		return messageSet, err
	}

	for offset < int32(messageSet.Size) {
		recordBatch, err := pd.ExtractRecordBatch(&offset)
		if err != nil {
			err = pd.JumpToOffset()
			if err != nil {
				return messageSet, err
			}
			return messageSet, nil
		}
		messageSet.RecordBatches = append(messageSet.RecordBatches, recordBatch)
	}

	if pd.isFlexible {
		err = pd.ExtractTagSection()
		if err != nil {
			return messageSet, err
		}
	}

	err = pd.JumpToOffset()
	if err != nil {
		return messageSet, err
	}
	return messageSet, nil
}
