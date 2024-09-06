package common

import (
	"unsafe"
)

type KInt interface {
	int8 | int16 | int32 | int64 | uint8 | uint16 | uint32 | uint64
}

type KFloat interface {
	float32 | float64
}

func LEndianBytesToKInt[T KInt](buf []byte, nBytes int) (T, bool) {
	var t T
	if nBytes > int(unsafe.Sizeof(t)) {
		return 0, false
	}
	if len(buf) < nBytes {
		return 0, false
	}

	var result T = 0
	for i := 0; i < nBytes; i++ {
		result = T(buf[nBytes-1-i]) | (result << 8)
	}
	return result, true
}

func LEndianBytesToFloat[T KFloat](buf []byte) T {
	return *(*T)(unsafe.Pointer(&buf))
}
