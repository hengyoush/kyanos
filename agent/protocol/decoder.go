package protocol

import (
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

/*
Extract until encounter the input string.

The sentinel string is not returned, but is still removed from the buffer.
*/
func (d *BinaryDecoder) ExtractStringUntil(sentinel string) (string, error) {
	idx := strings.Index(d.str, sentinel)
	if idx == -1 {
		return "", NewNotFoundError("Could not find sentinel character")
	}
	ret := d.str[0:idx]
	d.str = d.str[idx+len(sentinel):]
	d.readBytes += (idx + len(sentinel))
	return ret, nil
}

func (d *BinaryDecoder) ExtractString(length int) (string, error) {
	if len(d.str) < length {
		return "", NewResourceNotAvailbleError("Insufficient number of bytes.")
	}
	ret := d.str[0:length]
	d.str = d.str[length:]
	d.readBytes += length
	return ret, nil
}

func (d *BinaryDecoder) ExtractByte() (byte, error) {
	if len(d.str) < 1 {
		return 0, NewResourceNotAvailbleError("Insufficient number of bytes.")
	}
	x := d.str[0]
	d.str = d.str[1:]
	d.readBytes++
	return x, nil
}
