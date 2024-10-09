package mysql

import (
	"fmt"
	"kyanos/common"
	"unsafe"
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
	offset := int(kOKPacketHeaderOffset)
	_, ok := processLengthEncodedInt(packet.msg, &offset)
	if !ok {
		return false
	}
	// Parse last_insert_id.
	_, ok = processLengthEncodedInt(packet.msg, &offset)
	if !ok {
		return false
	}

	// Parse status flag.
	var status_flag int16
	ok = DissectInt[int16](packet.msg, &offset, 2, &status_flag)
	if !ok {
		return false
	}

	var warnings int16
	ok = DissectInt[int16](packet.msg, &offset, 2, &warnings)
	if !ok {
		return false
	}

	if warnings > 1000 {
		common.ProtocolParserLog.Infoln("Large warnings count is a sign of misclassification of OK packet.")
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

func isStmtPrepareOKPacket(packet *MysqlPacket) bool {
	return len(packet.msg) == 12 && packet.msg[0] == 0 && packet.msg[9] == 0
}

func DissectDateTimeParam(msg string, offset *int, param *string) bool {
	if len(msg) < *offset+1 {
		common.ProtocolParserLog.Infoln("Not enough bytes to dissect date/time param.")
		return false
	}

	length := msg[*offset]
	*offset = *offset + 1
	if len(msg) < *offset+int(length) {
		common.ProtocolParserLog.Infoln("Not enough bytes to dissect date/time param.")
		return false
	}
	*param = "MySQL DateTime rendering not implemented yet"
	*offset = *offset + int(length)
	return true
}

func DissectFloatParam[T common.KFloat](msg string, offset *int, params *string) bool {
	var t T
	length := int(unsafe.Sizeof(t))
	if len(msg) < *offset+length {
		common.ProtocolParserLog.Infoln("Not enough bytes to dissect float param.")
		return false
	}
	*params = fmt.Sprintf("%f", common.LEndianBytesToFloat[T]([]byte(msg[*offset:*offset+length])))
	*offset += length
	return true
}

func DissectIntParam[T common.KInt](s string, offset *int, nbytes uint, param *string) bool {
	var p int64
	DissectInt[int64](s, offset, int(nbytes), &p)
	*param = fmt.Sprintf("%d", p)
	return true
}

func DissectInt[T common.KInt](msg string, offset *int, length int, result *T) bool {
	if len(msg) < *offset+length {
		common.ProtocolParserLog.Infoln("Not enough bytes to dissect int param.")
		return false
	}
	*result, _ = common.LEndianBytesToKInt[T]([]byte(msg[*offset:]), length)
	*offset += length
	return true
}

// func dissectIntParam[T common.KInt](s string, offset uint, nbytes uint) (T, uint, bool) {
// 	if len(s)-int(offset) < int(nbytes) {
// 		common.Log.Errorln("Not enough bytes to dissect int param.")
// 		return 0, 0, false
// 	}
// 	result, ok := common.LEndianBytesToKInt[T]([]byte(s)[offset:], int(nbytes))
// 	return result, offset + nbytes, ok
// }

func processLengthEncodedInt(s string, offset *int) (int64, bool) {
	// If it is < 0xfb, treat it as a 1-byte integer.
	// If it is 0xfc, it is followed by a 2-byte integer.
	// If it is 0xfd, it is followed by a 3-byte integer.
	// If it is 0xfe, it is followed by a 8-byte integer.
	const kLencIntPrefix2b byte = 0xfc
	const kLencIntPrefix3b byte = 0xfd
	const kLencIntPrefix8b byte = 0xfe

	if len(s) == 0 {
		return -1, false
	}

	s = s[*offset:]

	if len(s) == 0 {
		return -1, false
	}
	checkLengthFunc := func(_s string, _len int) bool {
		if len(_s) < _len {
			return false
		}
		return true
	}
	var result int64
	switch s[0] {
	case kLencIntPrefix2b:
		s = s[1:]
		if ok := checkLengthFunc(s, 2); !ok {
			return -1, false
		}
		result, _ = common.LEndianBytesToKInt[int64]([]byte(s), 2)
		*offset = *offset + 1 + 2
	case kLencIntPrefix3b:
		s = s[1:]
		if ok := checkLengthFunc(s, 3); !ok {
			return -1, false
		}
		result, _ = common.LEndianBytesToKInt[int64]([]byte(s), 3)
		*offset = *offset + 1 + 3
	case kLencIntPrefix8b:
		s = s[1:]
		if ok := checkLengthFunc(s, 8); !ok {
			return -1, false
		}
		result, _ = common.LEndianBytesToKInt[int64]([]byte(s), 8)
		*offset = *offset + 1 + 8
	default:
		if ok := checkLengthFunc(s, 1); !ok {
			return -1, false
		}
		result, _ = common.LEndianBytesToKInt[int64]([]byte(s), 1)
		*offset = *offset + 1
	}
	return result, true
}

func DissectStringParam(s string, offset *int, param *string) bool {
	param_length, ok := processLengthEncodedInt(s, offset)
	if !ok || len(s) < *offset+int(param_length) {
		return false
	}
	*param = s[*offset : *offset+int(param_length)]
	*offset = *offset + int(param_length)
	return true
}

func CombinePrepareExecute(stmt_prepare_request string, params []StmtExecuteParam) string {
	result := fmt.Sprintf("query=[%s] params=[", stmt_prepare_request)
	for i, param := range params {
		result += param.value
		if i < len(params)-1 {
			result += ", "
		}
	}
	result += "]"
	return result
}

func MoreResultsExist(packet *MysqlPacket) bool {
	const kServerMoreResultsExistFlag int8 = 0x8
	if isOkPacket(packet) {
		pos := 1
		_, ok1 := processLengthEncodedInt(packet.msg, &pos)
		_, ok2 := processLengthEncodedInt(packet.msg, &pos)
		if !ok1 || !ok2 {
			common.ProtocolParserLog.Infoln("Error parsing OK packet for SERVER_MORE_RESULTS_EXIST_FLAG")
			return false
		}
		return int8(packet.msg[pos])&kServerMoreResultsExistFlag != 0
	}

	if isEOFPacket(packet, true) {
		const kEOFPacketStatusPos int = 3
		return packet.msg[kEOFPacketStatusPos]&byte(kServerMoreResultsExistFlag) != 0
	}
	return false
}
