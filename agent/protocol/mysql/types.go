package mysql

import (
	"fmt"
	"kyanos/agent/protocol"
	. "kyanos/agent/protocol"
)

const kMaxPacketLength int = (1 << 24) - 1

// Constants for StmtExecute packet, where the payload is as follows:
// bytes  description
//
//	1   [17] COM_STMT_EXECUTE
//	4   stmt-id
//	1   flags
//	4   iteration-count
const kStmtIDStartOffset int = 1
const kStmtIDBytes int = 4
const kFlagsBytes int = 1
const kIterationCountBytes int = 4

type command int
type ColType int
type RespStatus byte

const (
	kDecimal     ColType = 0x00
	kTiny        ColType = 0x01
	kShort       ColType = 0x02
	kLong        ColType = 0x03
	kFloat       ColType = 0x04
	kDouble      ColType = 0x05
	kNull        ColType = 0x06
	kTimestamp   ColType = 0x07
	kLongLong    ColType = 0x08
	kInt24       ColType = 0x09
	kDate        ColType = 0x0a
	kTimeColType ColType = 0x0b
	kDateTime    ColType = 0x0c
	kYear        ColType = 0x0d
	kVarChar     ColType = 0x0f
	kBit         ColType = 0x10
	kNewDecimal  ColType = 0xf6
	kEnum        ColType = 0xf7
	kSet         ColType = 0xf8
	kTinyBlob    ColType = 0xf9
	kMediumBlob  ColType = 0xfa
	kLongBlob    ColType = 0xfb
	kBlob        ColType = 0xfc
	kVarString   ColType = 0xfd
	kString      ColType = 0xfe
	kGeometry    ColType = 0xff
)

type StmtPrepareRespHeader struct {
	StmtId       int
	NumColumns   uint
	NumParams    uint
	WarningCount uint
}

/**
 * https://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html
 */
type StmtPrepareOKResponse struct {
	StmtPrepareRespHeader
	ColDefs   []ColDefinition
	ParamDefs []ColDefinition
}

/**
 * PreparedStatement holds a prepared statement string, and a parsed response,
 * which contains the placeholder column definitions.
 */
type PreparedStatement struct {
	Request  string
	Response StmtPrepareOKResponse
}

type StmtExecuteParam struct {
	ColType ColType
	value   string
}
type ColDefinition struct {
	Catalog      string
	Schema       string
	Table        string
	OrgTable     string
	Name         string
	OrgName      string
	NextLength   int8 // 总是0x0c
	CharacterSet int16
	ColumnLength int32
	ColumnType   ColType
	Flags        int16
	Decimals     int8
}

var _ ParsedMessage = &MysqlResponse{}
var _ StatusfulMessage = &MysqlResponse{}

type ResultsetRow struct {
	msg string
}

type MysqlResponse struct {
	protocol.FrameBase
	RespStatus
	Msg string
}

func (m *MysqlResponse) Status() ResponseStatus {
	if m.RespStatus == Ok {
		return SuccessStatus
	} else if m.RespStatus == Err {
		return FailStatus
	} else if m.RespStatus == Unknwon {
		return UnknownStatus
	} else {
		return NoneStatus
	}
}
func (m *MysqlResponse) FormatToSummaryString() string {
	return fmt.Sprintf("base=[%s] status=[%v] Msg=[%s]", m.FrameBase.String(), m.RespStatus, m.Msg)
}

// FormatToString implements protocol.ParsedMessage.
func (m *MysqlResponse) FormatToString() string {
	return fmt.Sprintf("base=[%s] status=[%v] Msg=[%s]", m.FrameBase.String(), m.RespStatus, m.Msg)
}

// IsReq implements protocol.ParsedMessage.
func (m *MysqlResponse) IsReq() bool {
	return false
}

const (
	Unknwon RespStatus = iota
	None
	Ok
	Err
)
const kRespHeaderEOF byte = 0xfe
const kRespHeaderErr byte = 0xff
const kRespHeaderOK byte = 0x00
const (
	kSleep            command = 0x00
	kQuit             command = 0x01
	kInitDB           command = 0x02
	kQuery            command = 0x03
	kFieldList        command = 0x04
	kCreateDB         command = 0x05
	kDropDB           command = 0x06
	kRefresh          command = 0x07
	kShutdown         command = 0x08
	kStatistics       command = 0x09
	kProcessInfo      command = 0x0a
	kConnect          command = 0x0b
	kProcessKill      command = 0x0c
	kDebug            command = 0x0d
	kPing             command = 0x0e
	kTime             command = 0x0f
	kDelayedInsert    command = 0x10
	kChangeUser       command = 0x11
	kBinlogDump       command = 0x12
	kTableDump        command = 0x13
	kConnectOut       command = 0x14
	kRegisterSlave    command = 0x15
	kStmtPrepare      command = 0x16
	kStmtExecute      command = 0x17
	kStmtSendLongData command = 0x18
	kStmtClose        command = 0x19
	kStmtReset        command = 0x1a
	kSetOption        command = 0x1b
	kStmtFetch        command = 0x1c
	kDaemon           command = 0x1d
	kBinlogDumpGTID   command = 0x1e
	kResetConnection  command = 0x1f
)

const (
	kDecimalbyte    byte = 0x00
	kTinybyte       byte = 0x01
	kShortbyte      byte = 0x02
	kLongbyte       byte = 0x03
	kFloatbyte      byte = 0x04
	kDoublebyte     byte = 0x05
	kNullbyte       byte = 0x06
	kTimestampbyte  byte = 0x07
	kLongLongbyte   byte = 0x08
	kInt24byte      byte = 0x09
	kDatebyte       byte = 0x0a
	kTimebyte       byte = 0x0b
	kDateTimebyte   byte = 0x0c
	kYearbyte       byte = 0x0d
	kVarCharbyte    byte = 0x0f
	kBitbyte        byte = 0x10
	kNewDecimalbyte byte = 0xf6
	kEnumbyte       byte = 0xf7
	kSetbyte        byte = 0xf8
	kTinyBlobbyte   byte = 0xf9
	kMediumBlobbyte byte = 0xfa
	kLongBlobbyte   byte = 0xfb
	kBlobbyte       byte = 0xfc
	kVarStringbyte  byte = 0xfd
	kStringbyte     byte = 0xfe
	kGeometrybyte   byte = 0xff
)

func parseCommand(b byte) (command, bool) {
	if b >= byte(kSleep) && b <= byte(kResetConnection) {
		return command(b), true
	} else {
		return -1, false
	}
}

type commandLengthRangesT map[command][2]int

var commandLengthRanges commandLengthRangesT

func InitCommandLengthRangs() {
	commandLengthRanges = make(commandLengthRangesT)
	commandLengthRanges[kSleep] = [2]int{1, 1}
	commandLengthRanges[kQuit] = [2]int{1, 1}
	commandLengthRanges[kInitDB] = [2]int{1, kMaxPacketLength}
	commandLengthRanges[kQuery] = [2]int{1, kMaxPacketLength}
	commandLengthRanges[kFieldList] = [2]int{2, kMaxPacketLength}
	commandLengthRanges[kCreateDB] = [2]int{1, kMaxPacketLength}
	commandLengthRanges[kDropDB] = [2]int{1, kMaxPacketLength}
	commandLengthRanges[kRefresh] = [2]int{2, 2}
	commandLengthRanges[kShutdown] = [2]int{1, 2}
	commandLengthRanges[kStatistics] = [2]int{1, 1}
	commandLengthRanges[kProcessInfo] = [2]int{1, 1}
	commandLengthRanges[kConnect] = [2]int{1, 1}
	commandLengthRanges[kProcessKill] = [2]int{1, 5}
	commandLengthRanges[kDebug] = [2]int{1, 1}
	commandLengthRanges[kPing] = [2]int{1, 1}
	commandLengthRanges[kTime] = [2]int{1, 1}
	commandLengthRanges[kDelayedInsert] = [2]int{1, 1}
	commandLengthRanges[kChangeUser] = [2]int{4, kMaxPacketLength}
	commandLengthRanges[kBinlogDump] = [2]int{11, kMaxPacketLength}
	commandLengthRanges[kTableDump] = [2]int{3, kMaxPacketLength}
	commandLengthRanges[kConnectOut] = [2]int{1, 1}
	commandLengthRanges[kRegisterSlave] = [2]int{18, kMaxPacketLength}
	commandLengthRanges[kStmtPrepare] = [2]int{1, kMaxPacketLength}
	commandLengthRanges[kStmtExecute] = [2]int{10, kMaxPacketLength}
	commandLengthRanges[kStmtSendLongData] = [2]int{7, kMaxPacketLength}
	commandLengthRanges[kStmtClose] = [2]int{5, 5}
	commandLengthRanges[kStmtReset] = [2]int{5, 5}
	commandLengthRanges[kSetOption] = [2]int{3, 3}
	commandLengthRanges[kStmtFetch] = [2]int{9, 9}
	commandLengthRanges[kDaemon] = [2]int{1, 1}
	commandLengthRanges[kBinlogDumpGTID] = [2]int{19, 19}
	commandLengthRanges[kResetConnection] = [2]int{1, 1}
}

var _ protocol.ProtocolStreamParser = &MysqlParser{}

// See https://dev.mysql.com/doc/internals/en/mysql-packet.html.
const kPacketHeaderLength int = 4

// Part of kPacketHeaderLength.
const kPayloadLengthLength int = 3

type State struct {
	PreparedStatements map[int]PreparedStatement
	active             bool
}
type ParseOptions struct {
	dumpResponse  bool
	dumpMaxRowNum int
}
type MysqlParser struct {
	*State
}

var _ ParsedMessage = &MysqlPacket{}

type MysqlPacket struct {
	FrameBase
	seqId byte
	msg   string
	cmd   int
	isReq bool
}

func (m *MysqlPacket) FormatToSummaryString() string {
	return fmt.Sprintf("base=[%s] seqId=[%d] msg=[%s] isReq=[%v]", m.FrameBase.String(), m.seqId, m.msg, m.isReq)
}

func (m *MysqlPacket) FormatToString() string {
	return fmt.Sprintf("base=[%s] seqId=[%d] msg=[%s] isReq=[%v]", m.FrameBase.String(), m.seqId, m.msg, m.isReq)
}

func (m *MysqlPacket) IsReq() bool {
	return m.isReq
}

type MysqlRequestPacket struct {
	MysqlPacket
	cmd byte
}
