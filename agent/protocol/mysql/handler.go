package mysql

import (
	"fmt"
	. "kyanos/agent/protocol"
	"kyanos/common"
)

func ProcessQuit(reqPacket *MysqlPacket, respView []ParsedMessage, record *Record) ParseState {
	record.Req = handleNonStringRequest(reqPacket)

	var response *MysqlResponse = &MysqlResponse{}
	if len(respView) == 0 {
		response.RespStatus = None
		response.SetTimeStamp(reqPacket.TimestampNs())
		record.Resp = response
		return Success
	}

	respPacket := respView[0].(*MysqlPacket)
	if isOkPacket(respPacket) {
		response.RespStatus = Ok
		response.FrameBase = respPacket.FrameBase
		record.Resp = response
		return Success
	}
	common.ProtocolParserLog.Warningln("Extra response packet after ComQuit.")
	return Invalid
}

func (p *MysqlParser) ProcessStmtFetch(reqPacket *MysqlPacket, respView []ParsedMessage, record *Record) ParseState {
	record.Req = handleNonStringRequest(reqPacket)
	record.Resp = &MysqlResponse{
		RespStatus: Unknwon,
	}
	return Ignore
}
func (p *MysqlParser) ProcessStmtReset(reqPacket *MysqlPacket, respView []ParsedMessage, record *Record) ParseState {
	return processRequestWithBasicResponse(reqPacket, false, respView, record)
}

func (p *MysqlParser) ProcessStmtClose(reqPacket *MysqlPacket, respView []ParsedMessage, record *Record) ParseState {
	// COM_CLOSE has no response.
	state := HandleStmtCloseRequest(reqPacket, p.PreparedStatements, record)
	if state != Success {
		return state
	}

	return handleNoResponse(reqPacket, respView, record)
}

func (p *MysqlParser) ProcessStmtExecute(reqPacket *MysqlPacket, respView []ParsedMessage, record *Record) ParseState {
	state := p.HandleStmtExecuteRequest(reqPacket, record)
	if state != Success {
		return state
	}

	if len(respView) == 0 {
		return NeedsMoreData
	}

	firstResp := respView[0]
	if isErrPacket(firstResp.(*MysqlPacket)) {
		state := handleErrMessage(respView, record)
		return state
	}

	if isOkPacket(firstResp.(*MysqlPacket)) {
		return handleOkMessage(respView, record)
	}

	return HandleResultsetResponse(reqPacket, true, false, respView, record)
}

func (p *MysqlParser) ProcessStmtSendLongData(reqPacket *MysqlPacket, respView []ParsedMessage, record *Record) ParseState {
	resultReq := handleNonStringRequest(reqPacket)
	record.Req = resultReq
	return handleNoResponse(reqPacket, respView, record)
}

func (p *MysqlParser) ProcessStmtPrepare(reqPacket *MysqlPacket, respView []ParsedMessage, record *Record) ParseState {
	var resultReq *MysqlPacket
	resultReq = handleStringRequest(reqPacket)
	record.Req = resultReq

	if len(respView) == 0 {
		return NeedsMoreData
	}
	firstResp := respView[0].(*MysqlPacket)
	if isErrPacket(firstResp) {
		handleErrMessage(respView, record)
		return Success
	}
	return p.handleStmtPrepareOKResponse(&respView, record)
}

func processQuery(reqPacket *MysqlPacket, respView []ParsedMessage, record *Record) ParseState {
	var resultReq *MysqlPacket
	resultReq = handleStringRequest(reqPacket)
	record.Req = resultReq

	if len(respView) == 0 {
		return NeedsMoreData
	}

	firstResp := respView[0].(*MysqlPacket)
	if isErrPacket(firstResp) {
		handleErrMessage(respView, record)
		return Success
	}

	if isOkPacket(firstResp) {
		return handleOkMessage(respView, record)
	}
	return HandleResultsetResponse(reqPacket, false, false, respView, record)
}

func processRequestWithBasicResponse(reqPacket *MysqlPacket, stringReq bool,
	respView []ParsedMessage, record *Record) ParseState {
	var resultReq *MysqlPacket
	if stringReq {
		resultReq = handleStringRequest(reqPacket)
	} else {
		resultReq = handleNonStringRequest(reqPacket)
	}
	record.Req = resultReq

	if len(respView) == 0 {
		return NeedsMoreData
	}

	if len(respView) > 1 {
		common.ProtocolParserLog.Warnf(
			"Did not expect more than one response packet [cmd=%s, num_extra_packets=%d].\n",
			reqPacket.msg, len(respView)-1)
		return Invalid
	}

	respPacket := respView[0].(*MysqlPacket)
	record.Resp = &MysqlResponse{
		FrameBase: respPacket.FrameBase,
	}
	if isOkPacket(respPacket) || isEOFPacketAll(respPacket) {
		return Success
	}

	if isErrPacket(respPacket) {
		return handleErrMessage(respView, record)
	}

	return Invalid
}

func HandleResultsetResponse(reqPacket *MysqlPacket, binaryResultset bool, multiResultset bool,
	respView []ParsedMessage, record *Record) ParseState {
	if len(respView) == 0 {
		return NeedsMoreData
	}
	firstResp := respView[0].(*MysqlPacket)
	respView = respView[1:]

	response := &MysqlResponse{
		FrameBase: firstResp.FrameBase,
	}
	record.Resp = response
	if multiResultset && isOkPacket(firstResp) {
		response.RespStatus = Ok
		return Success
	}

	paramOffset := 0
	numCol, ok := processLengthEncodedInt(firstResp.msg, &paramOffset)
	if !ok {
		response.RespStatus = Unknwon
		common.ProtocolParserLog.Warnln("Unable to process header packet of resultset response.")
		return Invalid
	}

	if paramOffset != len(firstResp.msg) {
		response.RespStatus = Unknwon
		common.ProtocolParserLog.Warnln("Extra bytes in length-encoded int packet.")
		return Invalid
	}

	if numCol == 0 {
		response.RespStatus = Unknwon
		common.ProtocolParserLog.Warnln("HandleResultsetResponse(): num columns should never be 0.")
		return Invalid
	}

	// A resultset has:
	//  1             column_count packet (*already accounted for*)
	//  column_count  column definition packets
	//  0 or 1        EOF packet (if CLIENT_DEPRECATE_EOF is false)
	//  0+            ResultsetRow packets (Spec says 1+, but have seen 0 in practice).
	//  1             OK or EOF packet
	// Must have at least the minimum number of remaining packets in a response.
	if len(respView) < int(numCol)+1 {
		response.RespStatus = Unknwon
		return NeedsMoreData
	}

	colDefs := make([]ColDefinition, 0)
	for i := 0; i < int(numCol); i++ {
		if len(respView) == 0 {
			return NeedsMoreData
		}
		packet := respView[0].(*MysqlPacket)
		respView = respView[1:]

		colDef, ok := ProcessColumnDefPacket(packet)
		if !ok {
			response.RespStatus = Unknwon
			common.ProtocolParserLog.Warnln("Expected column definition packet")
			return Invalid
		}

		colDefs = append(colDefs, *colDef)
	}

	if len(respView) == 0 {
		return NeedsMoreData
	}
	if isEOFPacketAll(respView[0].(*MysqlPacket)) {
		respView = respView[1:]
	}

	results := make([]ResultsetRow, 0)
	isLastPacket := func(p *MysqlPacket) bool {
		return isErrPacket(p) || isOkPacket(p) || isEOFPacketAll(p)
	}

	for len(respView) != 0 {
		rowPacket := respView[0].(*MysqlPacket)
		var status bool
		if binaryResultset {
			status = ProcessBinaryResultsetRowPacket(rowPacket, colDefs)
		} else {
			status = ProcessTextResultsetRowPacket(rowPacket, len(colDefs), record)
		}

		if status {
			respView = respView[1:]
			var row ResultsetRow = ResultsetRow{msg: rowPacket.msg}
			results = append(results, row)
			record.Resp.(*MysqlResponse).FrameBase.IncrByteSize(rowPacket.ByteSize())
		} else if isLastPacket(rowPacket) {
			break
		} else {
			response.RespStatus = Unknwon
			common.ProtocolParserLog.Warnf("Expected resultset row packet [OK=%v ERR=%v EOF=%v]",
				isOkPacket(rowPacket), isErrPacket(rowPacket),
				isEOFPacketAll(rowPacket))
			return Invalid
		}
	}

	if len(respView) == 0 {
		return NeedsMoreData
	}

	lastPacket := respView[0].(*MysqlPacket)
	if isErrPacket(respView[0].(*MysqlPacket)) {
		return handleErrMessage(respView, record)
	}
	respView = respView[1:]
	if multiResultset {
		response.Msg += ", "
	}
	response.Msg += fmt.Sprintf("Resultset rows = %d", len(results))
	if MoreResultsExist(lastPacket) {
		return HandleResultsetResponse(reqPacket, binaryResultset, true, respView, record)
	}
	if len(respView) != 0 {
		common.ProtocolParserLog.Warnf("Found %d extra packets", len(respView))
	}

	response.RespStatus = Ok
	response.SetTimeStamp(lastPacket.TimestampNs())
	return Success
}

func ProcessTextResultsetRowPacket(packet *MysqlPacket, numCol int, record *Record) bool {
	const kResultsetRowNullPrefix = '\xfb'
	if len(packet.msg) == 1 && packet.msg[0] == kResultsetRowNullPrefix {
		return true
	}
	var result string
	offset := 0
	for i := 0; i < numCol; i++ {
		ok := DissectStringParam(packet.msg, &offset, &result)
		if !ok {
			return false
		}
	}
	if offset < len(packet.msg) {
		common.ProtocolParserLog.Warnln("Have extra bytes in text resultset row.")
		return false
	}
	return true
}

func ProcessBinaryResultsetRowPacket(packet *MysqlPacket, columnDefs []ColDefinition) bool {

	const kBinaryResultsetRowHeaderOffset int = 1
	const kBinaryResultsetRowNullBitmapOffset int = 2
	const kBinaryResultsetRowNullBitmapByteFiller int = 7
	if packet.msg[0] != '\x00' {
		common.ProtocolParserLog.Warnln("Binary resultset row header mismatch.")
		return false
	}

	nullBitmapLen := (len(columnDefs) + kBinaryResultsetRowNullBitmapByteFiller +
		kBinaryResultsetRowNullBitmapOffset) / 8
	offset := kBinaryResultsetRowHeaderOffset + nullBitmapLen

	if offset >= len(packet.msg) {
		common.ProtocolParserLog.Warningln("Not enough bytes.")
	}

	nullBitmap := packet.msg[kBinaryResultsetRowHeaderOffset:nullBitmapLen]

	for i := 0; i < len(columnDefs); i++ {
		null_bitmap_bytepos := (i + kBinaryResultsetRowNullBitmapOffset) / 8
		null_bitmap_bitpos := (i + kBinaryResultsetRowNullBitmapOffset) % 8
		is_null := (nullBitmap[null_bitmap_bytepos] >> null_bitmap_bitpos) & 1

		if is_null == 1 {
			continue
		}

		var val string
		switch columnDefs[0].ColumnType {
		case kString:
			fallthrough
		case kVarChar:
			fallthrough
		case kVarString:
			fallthrough
		case kEnum:
			fallthrough
		case kSet:
			fallthrough
		case kLongBlob:
			fallthrough
		case kMediumBlob:
			fallthrough
		case kBlob:
			fallthrough
		case kTinyBlob:
			fallthrough
		case kGeometry:
			fallthrough
		case kBit:
			fallthrough
		case kDecimal:
			fallthrough
		case kNewDecimal:
			ok := DissectStringParam(packet.msg, &offset, &val)
			if !ok {
				return false
			}
		case kLongLong:
			ok := DissectIntParam[int64](packet.msg, &offset, 8, &val)
			if !ok {
				return false
			}
		case kLong:
			fallthrough
		case kInt24:
			ok := DissectIntParam[int32](packet.msg, &offset, 4, &val)
			if !ok {
				return false
			}
		case kShort:
			fallthrough
		case kYear:
			ok := DissectIntParam[int16](packet.msg, &offset, 2, &val)
			if !ok {
				return false
			}
		case kTiny:
			ok := DissectIntParam[int8](packet.msg, &offset, 1, &val)
			if !ok {
				return false
			}
		case kDouble:
			ok := DissectFloatParam[float64](packet.msg, &offset, &val)
			if !ok {
				return false
			}
		case kFloat:
			ok := DissectFloatParam[float32](packet.msg, &offset, &val)
			if !ok {
				return false
			}
		case kDate:
			fallthrough
		case kDateTime:
			fallthrough
		case kTimestamp:
			fallthrough
		case kTimeColType:
			ok := DissectDateTimeParam(packet.msg, &offset, &val)
			if !ok {
				return false
			}
		default:
			common.ProtocolParserLog.Warningln("Unrecognized result column type.")
		}
		common.ProtocolParserLog.Infof("col: %d, val: %v\n", i, val)
	}

	if offset != len(packet.msg) {

		common.ProtocolParserLog.Warningln("Extra bytes in binary resultset row.")
		return false
	}
	return true
}

func HandleStmtCloseRequest(reqPacket *MysqlPacket, prepareMap map[int]PreparedStatement, record *Record) ParseState {
	if len(reqPacket.msg) < 1+kStmtIDBytes {
		common.ProtocolParserLog.Warnln("Insufficient number of bytes for STMT_CLOSE")
		return Invalid
	}

	record.Req = reqPacket
	record.Req.(*MysqlPacket).msg = ""
	var stmt_id int32
	if len(reqPacket.msg) >= kStmtIDStartOffset+kStmtIDBytes {
		stmt_id, _ = common.LEndianBytesToKInt[int32]([]byte(reqPacket.msg[kStmtIDStartOffset:]), kStmtIDBytes)
	} else {
		// 处理错误情况，例如记录日志或返回错误
		common.ProtocolParserLog.Errorf("reqPacket.msg 长度不足")
	}
	_, ok := prepareMap[int(stmt_id)]
	if ok {
		delete(prepareMap, int(stmt_id))
	} else {
		common.ProtocolParserLog.Warnf("Could not find prepare statement for this close command [stmt_id=%d].", stmt_id)
	}
	return Success
}

func (p *MysqlParser) HandleStmtExecuteRequest(req *MysqlPacket, record *Record) ParseState {
	if len(req.msg) < 1+kStmtIDBytes {
		common.ProtocolParserLog.Warnln("Insufficient number of bytes for STMT_EXECUTE")
		return Invalid
	}
	record.Req = &(*req)
	stmt_id, _ := common.LEndianBytesToKInt[int32]([]byte(req.msg)[kStmtIDStartOffset:], kStmtIDBytes)
	stmt, ok := p.PreparedStatements[int(stmt_id)]
	if !ok {
		// There can be 2 possibilities in this case:
		// 1. The stitcher is confused/messed up and accidentally deleted wrong prepare event.
		// 2. Client sent a Stmt Exec for a deleted Stmt Prepare
		// We return -1 as stmt_id to indicate error and defer decision to the caller.

		// We can't determine whether the rest of this packet is valid or not, so just return success.
		// But pass the information up.
		common.ProtocolParserLog.Warnln("Could not find PREPARE statement for this EXECUTE command. Query not decoded. ")
		record.Req.(*MysqlPacket).msg = fmt.Sprintf("Execute stmt_id=%d.", stmt_id)
		return Success
	}
	num_params := stmt.Response.StmtPrepareRespHeader.NumParams
	offset := kStmtIDStartOffset + kStmtIDBytes + kFlagsBytes + kIterationCountBytes
	if len(req.msg) < offset {
		common.ProtocolParserLog.Warnln("Not a valid StmtExecuteRequest")
		return Invalid
	}
	// This is copied directly from the MySQL spec.
	null_bitmap_length := (num_params + 7) / 8
	offset += int(null_bitmap_length)
	stmt_bound := req.msg[offset]
	offset += 1

	params := make([]StmtExecuteParam, 0)
	if stmt_bound == 1 {
		// Offset to first param type and first param value respectively.
		// Each call to HandleStmtExecuteParam will advance the two offsets to their next positions.
		param_type_offset := offset
		param_val_offset := offset + 2*int(num_params)
		for i := 0; i < int(num_params); i++ {
			var param StmtExecuteParam
			ok := p.HandleStmtExecuteParam(req.msg, &param_type_offset, &param_val_offset, &param)
			if !ok {
				return Invalid
			}
			params = append(params, param)
		}
	}

	stmt_prepare_request := stmt.Request
	record.Req.(*MysqlPacket).msg = CombinePrepareExecute(stmt_prepare_request, params)
	return Success
}

func handleStringRequest(reqPacket *MysqlPacket) *MysqlPacket {
	if len(reqPacket.msg) == 0 {
		panic("A request cannot have an empty payload.")
	}
	request := *reqPacket
	cmd, _ := parseCommand(reqPacket.msg[0])
	request.cmd = int(cmd)
	request.msg = reqPacket.msg[1:]
	return &request
}

func handleNonStringRequest(reqPacket *MysqlPacket) *MysqlPacket {
	if len(reqPacket.msg) == 0 {
		panic("A request cannot have an empty payload.")
	}
	request := *reqPacket
	cmd, _ := parseCommand(reqPacket.msg[0])
	request.cmd = int(cmd)
	request.msg = reqPacket.msg[:]
	return &request
}

func handleOkMessage(respPackets []ParsedMessage, record *Record) ParseState {
	resp := respPackets[0].(*MysqlPacket)
	const kMinOKPacketSize int = 7
	if len(resp.msg) < kMinOKPacketSize {
		common.ProtocolParserLog.Warnln("Insufficient number of bytes for an OK packet.")
		return Invalid
	}
	record.Resp = &MysqlResponse{
		FrameBase: resp.FrameBase,
		Msg:       "OK",
	}
	if len(respPackets) > 1 {
		common.ProtocolParserLog.Warningf("Did not expect additional packets after OK packet [num_extra_packets=%d].",
			len(respPackets)-1)
		return Invalid
	}
	return Success
}
func handleNoResponse(reqPacket *MysqlPacket, respView []ParsedMessage, record *Record) ParseState {
	if len(respView) > 0 {
		common.ProtocolParserLog.Warnf("Did not expect any response packets [num_extra_packets=%d].", len(respView))
		return Invalid
	}
	record.Resp = &MysqlResponse{
		RespStatus: None,
		FrameBase:  NewFrameBase(reqPacket.TimestampNs(), 0, 0),
	}
	return Success
}

func handleErrMessage(respPackets []ParsedMessage, record *Record) ParseState {
	mysqlResp := respPackets[0].(*MysqlPacket)

	// Format of ERR packet:
	//   1  header: 0xff
	//   2  error_code
	//   1  sql_state_marker
	//   5  sql_state
	//   x  error_message
	// https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
	const kMinErrPacketSize int = 9
	const kErrorCodePos int = 1
	const kErrorCodeSize int = 2
	const kErrorMessagePos int = 9
	if len(mysqlResp.msg) < kMinErrPacketSize {
		common.ProtocolParserLog.Warnln("Insufficient number of bytes for an error packet.")
		return Invalid
	}
	if record.Resp == nil {
		record.Resp = &MysqlResponse{
			FrameBase: mysqlResp.FrameBase,
		}
	}
	record.Resp.(*MysqlResponse).Msg = mysqlResp.msg[kErrorMessagePos:]
	common.LEndianBytesToKInt[int32]([]byte(mysqlResp.msg[kErrorCodePos:]), kErrorCodeSize)
	if len(respPackets) > 1 {
		common.ProtocolParserLog.Warnf("Did not expect additional packets after error packet [num_extra_packets=%d].",
			len(respPackets)-1)
		return Invalid
	}
	return Success
}

func (p *MysqlParser) handleStmtPrepareOKResponse(respPacketsP *[]ParsedMessage, record *Record) ParseState {
	respPackets := *respPacketsP
	if len(respPackets) == 0 {
		return NeedsMoreData
	}

	firstResp := respPackets[0].(*MysqlPacket)
	respPackets = respPackets[1:]
	if !isStmtPrepareOKPacket(firstResp) {
		common.ProtocolParserLog.Warnln("Expected StmtPrepareOK packet")
		return Invalid
	}
	stmt_id, _ := common.LEndianBytesToKInt[int32]([]byte(firstResp.msg[1:]), 4)
	num_col, _ := common.LEndianBytesToKInt[int32]([]byte(firstResp.msg[5:]), 2)
	num_param, _ := common.LEndianBytesToKInt[int32]([]byte(firstResp.msg[7:]), 2)
	warning_count, _ := common.LEndianBytesToKInt[int32]([]byte(firstResp.msg[10:]), 2)

	min_expected_packets := num_col + num_param
	if int(min_expected_packets) > len(respPackets) {
		return NeedsMoreData
	}
	respHeader := StmtPrepareRespHeader{
		StmtId:       int(stmt_id),
		NumColumns:   uint(num_col),
		NumParams:    uint(num_param),
		WarningCount: uint(warning_count),
	}

	record.Resp = &MysqlResponse{FrameBase: firstResp.FrameBase}
	paramDefs := make([]ColDefinition, 0)
	for idx := 0; idx < int(num_param); idx++ {
		if len(respPackets) == 0 {
			return NeedsMoreData
		}

		paramDefPacket := respPackets[0].(*MysqlPacket)
		respPackets = respPackets[1:]
		colDel, ok := ProcessColumnDefPacket(paramDefPacket)
		if !ok {
			common.ProtocolParserLog.Warnln("Fail to process param definition packet.")
			return Invalid
		}
		paramDefs = append(paramDefs, *colDel)
		record.Resp.(*MysqlResponse).SetTimeStamp(paramDefPacket.TimestampNs())
	}

	if num_param != 0 {
		if len(respPackets) != 0 {
			eofPacket := respPackets[0].(*MysqlPacket)
			if isEOFPacketAll(eofPacket) {
				respPackets = respPackets[1:]
				record.Resp.(*MysqlResponse).SetTimeStamp(eofPacket.TimestampNs())
			}
		}
	}

	colDefs := make([]ColDefinition, 0)
	for i := 0; i < int(num_col); i++ {
		if len(respPackets) == 0 {
			return NeedsMoreData
		}

		colDefPacket := respPackets[0].(*MysqlPacket)
		respPackets = respPackets[1:]
		colDel, ok := ProcessColumnDefPacket(colDefPacket)
		if !ok {
			common.ProtocolParserLog.Warnln("Fail to process column definition packet.")
			return Invalid
		}
		colDefs = append(colDefs, *colDel)
		record.Resp.(*MysqlResponse).SetTimeStamp(colDefPacket.TimestampNs())
	}
	if num_col != 0 {
		if len(respPackets) != 0 {
			eofPacket := respPackets[0].(*MysqlPacket)
			if isEOFPacketAll(eofPacket) {
				respPackets = respPackets[1:]
				record.Resp.(*MysqlResponse).SetTimeStamp(eofPacket.TimestampNs())
			}
		}
	}

	if len(respPackets) > 0 {
		common.ProtocolParserLog.Warnln("Extra packets")
	}
	p.PreparedStatements[int(stmt_id)] = PreparedStatement{
		Request: record.Req.(*MysqlPacket).msg,
		Response: StmtPrepareOKResponse{
			StmtPrepareRespHeader: respHeader,
			ColDefs:               colDefs,
			ParamDefs:             paramDefs,
		},
	}
	record.Resp.(*MysqlResponse).RespStatus = Ok
	return Success
}

func ProcessColumnDefPacket(packet *MysqlPacket) (*ColDefinition, bool) {
	var colDef ColDefinition
	offset := 0
	ok := DissectStringParam(packet.msg, &offset, &colDef.Catalog)
	if !ok {
		return nil, false
	}
	if colDef.Catalog != "def" {
		common.ProtocolParserLog.Warnln("ColumnDef Packet must start with `def`.")
		return nil, false
	}
	ok = DissectStringParam(packet.msg, &offset, &colDef.Schema)
	if !ok {
		return nil, false
	}

	ok = DissectStringParam(packet.msg, &offset, &colDef.Table)
	if !ok {
		return nil, false
	}
	ok = DissectStringParam(packet.msg, &offset, &colDef.OrgTable)
	if !ok {
		return nil, false
	}
	ok = DissectStringParam(packet.msg, &offset, &colDef.Name)
	if !ok {
		return nil, false
	}
	ok = DissectStringParam(packet.msg, &offset, &colDef.OrgName)
	if !ok {
		return nil, false
	}
	result, ok := processLengthEncodedInt(packet.msg, &offset)
	colDef.NextLength = int8(result)
	if colDef.NextLength != 12 {
		common.ProtocolParserLog.Warnln("ColumnDef Packet's next_length field is always 0x0c.")
		return nil, false
	}

	ok = DissectInt[int16](packet.msg, &offset, 2, &colDef.CharacterSet)
	if !ok {
		return nil, false
	}

	ok = DissectInt[int32](packet.msg, &offset, 4, &colDef.ColumnLength)
	if !ok {
		return nil, false
	}

	var colType int8
	ok = DissectInt[int8](packet.msg, &offset, 1, &colType)
	if !ok {
		return nil, false
	}
	colDef.ColumnType = ColType(colType)

	ok = DissectInt[int16](packet.msg, &offset, 2, &colDef.Flags)
	if !ok {
		return nil, false
	}

	ok = DissectInt[int8](packet.msg, &offset, 1, &colDef.Decimals)
	if !ok {
		return nil, false
	}
	return &colDef, true
}

// Spec on how to dissect params is here:
// https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
//
// List of parameter types is followed by list of parameter values,
// so we have two offset pointers, one that points to current type position,
// and one that points to current value position
func (p *MysqlParser) HandleStmtExecuteParam(msg string, typeOffset *int, valOffset *int, param *StmtExecuteParam) bool {
	param.ColType = ColType(msg[*typeOffset])
	// panic("todo")
	*typeOffset = *typeOffset + 2
	switch param.ColType {
	case kString:
		fallthrough
	case kVarChar:
		fallthrough
	case kVarString:
		fallthrough
	case kEnum:
		fallthrough
	case kSet:
		fallthrough
	case kLongBlob:
		fallthrough
	case kMediumBlob:
		fallthrough
	case kBlob:
		fallthrough
	case kTinyBlob:
		fallthrough
	case kGeometry:
		fallthrough
	case kBit:
		fallthrough
	case kDecimal:
		fallthrough
	case kNewDecimal:
		ok := DissectStringParam(msg, valOffset, &param.value)
		if !ok {
			return false
		}
	case kTiny:
		ok := DissectIntParam[int8](msg, valOffset, 1, &param.value)
		if !ok {
			return false
		}
	case kShort:
	case kYear:
		ok := DissectIntParam[int16](msg, valOffset, 2, &param.value)
		if !ok {
			return false
		}
	case kLong:
	case kInt24:
		ok := DissectIntParam[int32](msg, valOffset, 4, &param.value)
		if !ok {
			return false
		}
	case kLongLong:
		ok := DissectIntParam[int64](msg, valOffset, 8, &param.value)
		if !ok {
			return false
		}
	case kFloat:
		ok := DissectFloatParam[float32](msg, valOffset, &param.value)
		if !ok {
			return false
		}
	case kDouble:
		ok := DissectFloatParam[float64](msg, valOffset, &param.value)
		if !ok {
			return false
		}
	case kDate:
	case kDateTime:
	case kTimestamp:
		ok := DissectDateTimeParam(msg, valOffset, &param.value)
		if !ok {
			return false
		}
	case kTimeColType:
		ok := DissectDateTimeParam(msg, valOffset, &param.value)
		if !ok {
			return false
		}
	case kNull:
	default:
		common.ProtocolParserLog.Fatalf("Unexpected/unhandled column type %d",
			param.ColType)
	}
	return true
}
