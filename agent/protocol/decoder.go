package protocol

import (
	"reflect"
	"strings"
)

type BinaryDecoder struct {
	buf       []byte
	str       string
	readBytes int
}

func NewBinaryDecoder(buf []byte) *BinaryDecoder {
	return &BinaryDecoder{buf: buf, str: string(buf)}
}
func (b *BinaryDecoder) RemainingBytes() int {
	return len(b.str)
}

func (b *BinaryDecoder) Buf() []byte {
	return b.buf
}
func (b *BinaryDecoder) SubBuf(length int) []byte {
	return b.buf[len(b.buf)-len(b.str)+length:]
}

func (b *BinaryDecoder) SetBuf(buf []byte) {
	b.buf = buf
	b.str = string(buf)
}

type NotFoundError struct {
	msg string
}

func NewNotFoundError(msg string) *NotFoundError {
	return &NotFoundError{
		msg: msg,
	}
}
func (e *NotFoundError) Error() string {
	return e.msg
}

type ResourceNotAvailbleError struct {
	msg string
}

func NewResourceNotAvailbleError(msg string) *NotFoundError {
	m := msg
	if m == "" {
		m = "Resource not available"
	}
	return &NotFoundError{msg}
}
func (e *ResourceNotAvailbleError) Error() string {
	return e.msg
}
func (d *BinaryDecoder) ReadBytes() int {
	return d.readBytes
}

var ResourceNotAvailble = NewResourceNotAvailbleError("Insufficient number of bytes.")
var NotFound = NewNotFoundError("Could not find sentinel character")

/*
Extract until encounter the input string.

The sentinel string is not returned, but is still removed from the buffer.
*/
func (d *BinaryDecoder) ExtractStringUntil(sentinel string) (string, error) {
	idx := strings.Index(d.str, sentinel)
	if idx == -1 {
		return "", NotFound
	}
	ret := d.str[0:idx]
	d.str = d.str[idx+len(sentinel):]
	d.readBytes += (idx + len(sentinel))
	return ret, nil
}

func (d *BinaryDecoder) ExtractString(length int) (string, error) {
	if len(d.str) < length {
		return "", ResourceNotAvailble
	}
	ret := d.str[0:length]
	d.str = d.str[length:]
	d.readBytes += length
	return ret, nil
}

func (d *BinaryDecoder) ExtractByte() (byte, error) {
	if len(d.str) < 1 {
		return 0, ResourceNotAvailble
	}
	x := d.str[0]
	d.str = d.str[1:]
	d.readBytes++
	return x, nil
}

func ExtractBEInt[TIntType int8 | int16 | int32 | uint32 | uint8 | int64](d *BinaryDecoder) (TIntType, error) {
	typeSize := int(reflect.TypeOf(TIntType(0)).Size())
	if len(d.str) < typeSize {
		return 0, ResourceNotAvailble
	}
	var x TIntType = 0
	for i := 0; i < typeSize; i++ {
		x = TIntType(d.str[i]) | (x << 8)
	}
	d.str = d.str[typeSize:]
	d.readBytes += typeSize
	return x, nil
}

func ExtractLEInt[TIntType int32 | uint32 | uint8](d *BinaryDecoder) (TIntType, error) {
	typeSize := int(reflect.TypeOf(TIntType(0)).Size())
	if len(d.str) < 4 {
		return 0, ResourceNotAvailble
	}
	var x TIntType = 0
	for i := 0; i < typeSize; i++ {
		x = TIntType(d.str[typeSize-1-i]) | (x << 8)
	}
	d.str = d.str[typeSize:]
	d.readBytes += typeSize
	return x, nil
}

func BEndianBytesToInt[TIntType int32 | uint32 | uint8](d *BinaryDecoder) TIntType {
	typeSize := int(reflect.TypeOf(TIntType(0)).Size())
	if len(d.str) < typeSize {
		return 0
	}
	var x TIntType = 0
	for i := 0; i < typeSize; i++ {
		x = TIntType(d.str[i]) | (x << 8)
	}
	return x
}

func LEndianBytesToInt[TIntType int32 | uint32 | uint8](d *BinaryDecoder) TIntType {
	typeSize := int(reflect.TypeOf(TIntType(0)).Size())
	if len(d.str) < 4 {
		return 0
	}
	var x TIntType = 0
	for i := 0; i < typeSize; i++ {
		x = TIntType(d.str[typeSize-1-i]) | (x << 8)
	}
	return x
}
