package protocol

import "strings"

const fakeDataMarkPrefix = "__FAKE_DATA__"
const fakeDataMarkLen = len(fakeDataMarkPrefix) + 4

func MakeNewFakeData(size uint32) ([]byte, bool) {
	if size < uint32(fakeDataMarkLen) {
		return nil, false
	} else {
		buf := make([]byte, size)
		copy(buf, fakeDataMarkPrefix)
		size -= uint32(fakeDataMarkLen)
		lenByte := []byte{byte(size >> 24), byte(size >> 16), byte(size >> 8), byte(size)}
		buf[fakeDataMarkLen] = lenByte[0]
		buf[fakeDataMarkLen+1] = lenByte[1]
		buf[fakeDataMarkLen+2] = lenByte[2]
		buf[fakeDataMarkLen+3] = lenByte[3]
		return buf, true
	}
}

func fakeDataMarkIndex(buf []byte) (int, bool) {
	if len(buf) < fakeDataMarkLen {
		return -1, false
	}
	idx := strings.Index(string(buf), fakeDataMarkPrefix)
	if idx < 0 {
		return -1, false
	}
	return idx, true
}

func getFakeDataSize(buf []byte, pos int) uint32 {
	buf = buf[pos:]
	if len(buf) < fakeDataMarkLen {
		return 0
	} else {
		return uint32(buf[fakeDataMarkLen])<<24 | uint32(buf[fakeDataMarkLen+1])<<16 | uint32(buf[fakeDataMarkLen+2])<<8 | uint32(buf[fakeDataMarkLen+3])
	}
}
