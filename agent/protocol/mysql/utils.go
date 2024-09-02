package mysql

import (
	"kyanos/common"
)

func isErrPacket(packet *MysqlPacket) bool {
	return packet.msg[0] == kRespHeaderErr && len(packet.msg) > 3
}

/**
 * https://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html
 */
func isEOFPacket(packet *MysqlPacket, protocol41 bool) bool {
	var expectedSize int
	if protocol41 {
		expectedSize = 5
	} else {
		expectedSize = 1
	}
	header := packet.msg[0]
	return header == kRespHeaderEOF && len(packet.msg) == expectedSize
}

func isEOFPacketAll(packet *MysqlPacket) bool {
	return isEOFPacket(packet, true) || isEOFPacket(packet, false)
}

func isOkPacket(packet *MysqlPacket) bool {
	const kOKPacketHeaderOffset byte = 1
	header := packet.msg[0]

	// Parse affected_rows.
	offset := uint(kOKPacketHeaderOffset)
	offset, _, ok := processLengthEncodedInt(packet.msg, offset)
	if !ok {
		return false
	}
	// Parse last_insert_id.
	offset, _, ok = processLengthEncodedInt(packet.msg, offset)
	if !ok {
		return false
	}

	// Parse status flag.
	_, offset, ok = readNBytesToInt[int16](packet.msg, offset, 2)
	if !ok {
		return false
	}

	var warnings int16
	warnings, offset, ok = readNBytesToInt[int16](packet.msg, offset, 2)
	if !ok {
		return false
	}

	if warnings > 1000 {
		common.Log.Warnln("Large warnings count is a sign of misclassification of OK packet.")
	}

	// 7 byte minimum packet size in protocol 4.1.
	if (header == kRespHeaderOK) && len(packet.msg) >= 7 {
		return true
	}

	if (header == kRespHeaderEOF) && len(packet.msg) < 9 && !isEOFPacketAll(packet) {
		return true
	}
	return false
}

func readNBytesToInt[T common.KInt](s string, offset uint, nbytes uint) (T, uint, bool) {
	if len(s)-int(offset) < int(nbytes) {
		common.Log.Errorln("Not enough bytes to dissect int param.")
		return 0, 0, false
	}
	result, ok := common.LEndianBytesToKInt[T]([]byte(s)[offset:], int(nbytes))
	return result, offset + nbytes, ok
}

func processLengthEncodedInt(s string, offset uint) (uint, uint, bool) {
	// If it is < 0xfb, treat it as a 1-byte integer.
	// If it is 0xfc, it is followed by a 2-byte integer.
	// If it is 0xfd, it is followed by a 3-byte integer.
	// If it is 0xfe, it is followed by a 8-byte integer.
	const kLencIntPrefix2b byte = 0xfc
	const kLencIntPrefix3b byte = 0xfd
	const kLencIntPrefix8b byte = 0xfe

	if len(s) == 0 {
		common.Log.Errorln("Not enough bytes to extract length-encoded int")
		return 0, 0, false
	}

	s = s[offset:]

	if len(s) == 0 {
		common.Log.Errorln("Not enough bytes to extract length-encoded int")
		return 0, 0, false
	}
	checkLengthFunc := func(_s string, _len int) bool {
		if len(_s) < _len {
			common.Log.Errorln("Not enough bytes to extract length-encoded int")
			return false
		}
		return true
	}
	var result int64
	var newOffset uint
	switch s[0] {
	case kLencIntPrefix2b:
		s = s[1:]
		if ok := checkLengthFunc(s, 2); !ok {
			return 0, 0, false
		}
		result = int64(common.LEndianBytesToLong([]byte(s), 2))
		newOffset = offset + 1 + 2
	case kLencIntPrefix3b:
		s = s[1:]
		if ok := checkLengthFunc(s, 3); !ok {
			return 0, 0, false
		}
		result = int64(common.LEndianBytesToLong([]byte(s), 3))
		newOffset = offset + 1 + 3
	case kLencIntPrefix8b:
		s = s[1:]
		if ok := checkLengthFunc(s, 8); !ok {
			return 0, 0, false
		}
		result = int64(common.LEndianBytesToLong([]byte(s), 8))
		newOffset = offset + 1 + 8
	default:
		if ok := checkLengthFunc(s, 1); !ok {
			return 0, 0, false
		}
		result = int64(common.LEndianBytesToLong([]byte(s), 1))
		newOffset = offset + 1
	}
	return newOffset, uint(result), true
}
