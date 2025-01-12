package decoder

import (
	"errors"
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/kafka/common"
)

const (
	kFirstBitMask     = 0x80
	kLastSevenBitMask = 0x7f
	kByteLength       = 7
)

func ExtractBytesCore(len int, binaryDecoder *protocol.BinaryDecoder) (string, error) {
	tbuf, err := binaryDecoder.ExtractString(len)
	if err != nil {
		return "", err
	}
	return tbuf, nil
}

func ExtractUnsignedVarintCore(maxLength int, binaryDecoder *protocol.BinaryDecoder) (int64, error) {
	value := int64(0)
	for i := 0; i < maxLength; i += kByteLength {
		b, err := binaryDecoder.ExtractByte()
		if err != nil {
			return 0, err
		}
		b64 := int64(b)
		if b64&kFirstBitMask == 0 {
			value |= b64 << i
			return value, nil
		}
		value |= int64(b64&kLastSevenBitMask) << i
	}
	return 0, errors.New("extract varint core failure")
}
func ExtractVarintCore(maxLength int, binaryDecoder *protocol.BinaryDecoder) (int64, error) {
	value, err := ExtractUnsignedVarintCore(maxLength, binaryDecoder)
	if err != nil {
		return 0, err
	}
	return (int64(uint64(value) >> 1)) ^ (-(value & 1)), nil
}

type PacketDecoder struct {
	markedBufs    [][]byte
	binaryDecoder *protocol.BinaryDecoder
	apiKey        common.APIKey
	apiVersion    int16
	isFlexible    bool
}

func NewPacketDecoder(buf []byte) *PacketDecoder {
	return &PacketDecoder{
		markedBufs:    [][]byte{},
		binaryDecoder: protocol.NewBinaryDecoder(buf),
	}
}

func (pd *PacketDecoder) ExtractBool() (bool, error) {
	val, err := pd.ExtractInt8()
	if err != nil {
		return false, err
	}
	return val != 0, nil
}

func (pd *PacketDecoder) ExtractInt8() (int8, error) {
	return protocol.ExtractBEInt[int8](pd.binaryDecoder)
}

func (pd *PacketDecoder) ExtractInt16() (int16, error) {
	return protocol.ExtractBEInt[int16](pd.binaryDecoder)
}

func (pd *PacketDecoder) ExtractInt32() (int32, error) {
	return protocol.ExtractBEInt[int32](pd.binaryDecoder)
}

func (pd *PacketDecoder) ExtractInt64() (int64, error) {
	return protocol.ExtractBEInt[int64](pd.binaryDecoder)
}

func (pd *PacketDecoder) ExtractUnsignedVarint() (int32, error) {
	const kVarintMaxLength = 35
	val, err := ExtractUnsignedVarintCore(kVarintMaxLength, pd.binaryDecoder)
	return int32(val), err
}

func (pd *PacketDecoder) ExtractVarint() (int32, error) {
	const kVarintMaxLength = 35
	val, err := ExtractVarintCore(kVarintMaxLength, pd.binaryDecoder)
	return int32(val), err
}

func (pd *PacketDecoder) ExtractVarlong() (int64, error) {
	const kVarlongMaxLength = 70
	return ExtractVarintCore(kVarlongMaxLength, pd.binaryDecoder)
}
func (pd *PacketDecoder) ExtractRegularString() (string, error) {
	len, err := pd.ExtractInt16()
	if err != nil {
		return "", err
	}
	return ExtractBytesCore(int(len), pd.binaryDecoder)
}

func (pd *PacketDecoder) ExtractRegularNullableString() (string, error) {
	len, err := pd.ExtractInt16()
	if err != nil {
		return "", err
	}
	if len == -1 {
		return "", nil
	}
	return ExtractBytesCore(int(len), pd.binaryDecoder)
}

func (pd *PacketDecoder) ExtractCompactString() (string, error) {
	len, err := pd.ExtractUnsignedVarint()
	if err != nil {
		return "", err
	}
	// length N + 1 is encoded.
	len -= 1
	if len < 0 {
		return "", errors.New("Compact String has negative length.")
	}
	return ExtractBytesCore(int(len), pd.binaryDecoder)
}

func (pd *PacketDecoder) ExtractCompactNullableString() (string, error) {
	len, err := pd.ExtractUnsignedVarint()
	if err != nil {
		return "", err
	}
	// length N + 1 is encoded.
	len -= 1
	if len < -1 {
		return "", errors.New("Compact String has negative length.")
	}
	if len == -1 {
		return "", nil
	}
	return ExtractBytesCore(int(len), pd.binaryDecoder)
}

func (pd *PacketDecoder) ExtractString() (string, error) {
	if pd.isFlexible {
		return pd.ExtractCompactString()
	}
	return pd.ExtractRegularString()
}

func (pd *PacketDecoder) ExtractNullableString() (string, error) {
	if pd.isFlexible {
		return pd.ExtractCompactNullableString()
	}
	return pd.ExtractRegularNullableString()
}
func (pd *PacketDecoder) ExtractRegularBytes() (string, error) {
	len, err := pd.ExtractInt16()
	if err != nil {
		return "", err
	}
	return ExtractBytesCore(int(len), pd.binaryDecoder)
}

func (pd *PacketDecoder) ExtractRegularNullableBytes() (string, error) {
	len, err := pd.ExtractInt16()
	if err != nil {
		return "", err
	}
	if len == -1 {
		return "", nil
	}
	return ExtractBytesCore(int(len), pd.binaryDecoder)
}

func (pd *PacketDecoder) ExtractCompactBytes() (string, error) {
	len, err := pd.ExtractUnsignedVarint()
	if err != nil {
		return "", err
	}
	// length N + 1 is encoded.
	len -= 1
	if len < 0 {
		return "", errors.New("Compact Bytes has negative length.")
	}
	return ExtractBytesCore(int(len), pd.binaryDecoder)
}

func (pd *PacketDecoder) ExtractCompactNullableBytes() (string, error) {
	len, err := pd.ExtractUnsignedVarint()
	if err != nil {
		return "", err
	}
	// length N + 1 is encoded.
	len -= 1
	if len < -1 {
		return "", errors.New("Compact Bytes has negative length.")
	}
	if len == -1 {
		return "", nil
	}
	return ExtractBytesCore(int(len), pd.binaryDecoder)
}

func (pd *PacketDecoder) ExtractBytes() (string, error) {
	if pd.isFlexible {
		return pd.ExtractCompactBytes()
	}
	return pd.ExtractRegularBytes()
}

func (pd *PacketDecoder) ExtractNullableBytes() (string, error) {
	if pd.isFlexible {
		return pd.ExtractCompactNullableBytes()
	}
	return pd.ExtractRegularNullableBytes()
}

func (pd *PacketDecoder) ExtractBytesZigZag() (string, error) {
	len, err := pd.ExtractVarint()
	if err != nil {
		return "", err
	}
	if len < -1 {
		return "", errors.New("Not enough bytes in ExtractBytesZigZag.")
	}
	if len == 0 || len == -1 {
		return "", nil
	}
	return ExtractBytesCore(int(len), pd.binaryDecoder)
}
func (pd *PacketDecoder) ExtractTagSection() error {
	if !pd.isFlexible {
		return nil
	}

	numFields, err := pd.ExtractUnsignedVarint()
	if err != nil {
		return err
	}
	for i := 0; i < int(numFields); i++ {
		_, err := pd.ExtractTaggedField()
		if err != nil {
			return err
		}
	}
	return nil
}

func (pd *PacketDecoder) ExtractTaggedField() (bool, error) {
	pd.ExtractUnsignedVarint()
	len, err := pd.ExtractUnsignedVarint()
	if err != nil {
		return false, err
	}
	ExtractBytesCore(int(len), pd.binaryDecoder)
	return true, nil
}

func (pd *PacketDecoder) ExtractReqHeader(req *common.Request) (bool, error) {
	// parse header and fill req
	apiKey, err := pd.ExtractInt16()
	if err != nil {
		return false, err
	}
	req.Apikey = common.APIKey(apiKey)
	apiVersion, err := pd.ExtractInt16()
	if err != nil {
		return false, err
	}
	req.ApiVersion = apiVersion

	pd.SetAPIInfo(req.Apikey, req.ApiVersion)
	_, err = pd.ExtractInt32()
	if err != nil {
		return false, err
	}
	req.ClientId, err = pd.ExtractRegularNullableString()
	if err != nil {
		return false, err
	}

	err = pd.ExtractTagSection()
	if err != nil {
		return false, err
	}
	return true, nil
}
func (pd *PacketDecoder) ExtractRespHeader(resp *common.Response) error {
	if _, err := pd.ExtractInt32(); err != nil {
		return err
	}
	if err := pd.ExtractTagSection(); err != nil {
		return err
	}
	return nil
}
func (pd *PacketDecoder) SetAPIInfo(apiKey common.APIKey, apiVersion int16) {
	pd.apiKey = apiKey
	pd.apiVersion = apiVersion
	pd.isFlexible = common.IsFlexible(apiKey, apiVersion)
}

func ExtractRegularArray[T any](extractFunc func() (T, error), pd *PacketDecoder) ([]T, error) {
	const kNullSize = -1

	len, err := pd.ExtractInt32()
	if err != nil {
		return nil, err
	}
	if len < kNullSize {
		return nil, errors.New("length of array cannot be negative")
	}
	if len == kNullSize {
		return []T{}, nil
	}

	result := make([]T, len)
	for i := 0; i < int(len); i++ {
		tmp, err := extractFunc()
		if err != nil {
			return nil, err
		}
		result[i] = tmp
	}
	return result, nil
}

func ExtractCompactArray[T any](extractFunc func() (T, error), pd *PacketDecoder) ([]T, error) {
	len, err := pd.ExtractUnsignedVarint()
	if err != nil {
		return nil, err
	}
	if len < 0 {
		return nil, errors.New("length of array cannot be negative")
	}
	if len == 0 {
		return []T{}, nil
	}
	// Length N + 1 is encoded.
	len -= 1

	result := make([]T, len)
	for i := 0; i < int(len); i++ {
		tmp, err := extractFunc()
		if err != nil {
			return nil, err
		}
		result[i] = tmp
	}
	return result, nil
}

func ExtractArray[T any](extractFunc func() (T, error), pd *PacketDecoder) ([]T, error) {
	if pd.isFlexible {
		return ExtractCompactArray(extractFunc, pd)
	}
	return ExtractRegularArray(extractFunc, pd)
}

func (pd *PacketDecoder) MarkOffset(_len int32) error {
	if _len < 0 {
		return errors.New("length cannot be negative")
	}
	if int(_len) > pd.binaryDecoder.RemainingBytes() {
		return errors.New("not enough bytes in MarkOffset")
	}
	pd.markedBufs = append(pd.markedBufs, pd.binaryDecoder.SubBuf(int(_len)))
	return nil
}

func (pd *PacketDecoder) JumpToOffset() error {
	if len(pd.markedBufs) == 0 {
		return errors.New("no marked buffer to jump to")
	}
	pd.binaryDecoder.SetBuf(pd.markedBufs[len(pd.markedBufs)-1])
	pd.markedBufs = pd.markedBufs[:len(pd.markedBufs)-1]
	return nil
}
