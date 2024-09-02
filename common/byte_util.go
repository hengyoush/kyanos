package common

import "reflect"

type KInt interface {
	int16 | int32 | int64
}

/**
 * Convert a little-endian string of bytes to an integer.
 *
 * @tparam T The receiver int type.
 * @tparam N Number of bytes to process from the source buffer. N must be <= sizeof(T).
 * If N < sizeof(T), the remaining bytes (MSBs) are assumed to be zero.
 * @param buf The sequence of bytes.
 * @return The decoded int value.
 */
func LEndianBytesToInt(buf []byte, nBytes int) int {
	if nBytes > 4 {
		panic("invalid nbytes")
	}
	if len(buf) < nBytes {
		panic("len(buf) < nBytes!")
	}

	result := 0
	for i := 0; i < nBytes; i++ {
		result = int(buf[nBytes-1-i]) | (result << 8)
	}
	return result
}

func LEndianBytesToLong(buf []byte, nBytes int) int64 {
	if nBytes > 8 {
		panic("invalid nbytes")
	}
	if len(buf) < nBytes {
		panic("len(buf) < nBytes!")
	}

	var result int64 = 0
	for i := 0; i < nBytes; i++ {
		result = int64(buf[nBytes-1-i]) | (result << 8)
	}
	return result
}

func LEndianBytesToKInt[T KInt](buf []byte, nBytes int) (T, bool) {
	var t T
	if nBytes > reflect.TypeOf(t).Len() {
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
