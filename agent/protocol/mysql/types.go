package mysql

const kMaxPacketLength int = (1 << 24) - 1

type command int
type RespStatus byte

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
