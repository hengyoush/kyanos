package mongodb

type opType int32

const (
	kOPReply       int32 = 1
	kOPUpdate      int32 = 2001
	kOPInsert      int32 = 2002
	kReserved      int32 = 2003
	kOPQuery       int32 = 2004
	kOPGetMore     int32 = 2005
	kOPDelete      int32 = 2006
	kOPKillCursors int32 = 2007
	kOPCompressed  int32 = 2012
	kOPMsg         int32 = 2013
)

const (
	kHeaderLength      uint8 = 16
	kMessageLengthSize uint8 = 4
	kSectionLengthSize uint8 = 4
	kHeaderAndFlagSize uint8 = 20

	kChecksumBitmask       uint32 = 1
	kMoreToComeBitmask     uint32 = 1 << 1
	kExhaustAllowedBitmask uint32 = 1 << 16
	kRequiredUnsetBitmask  uint32 = 0xFFFC
)

type Section struct {
	kind      uint8
	length    int32
	Documents []string
}

func (s *Section) Kind() uint8 {
	return s.kind
}
func (s *Section) Length() int32 {
	return s.length
}

const (
	kSectionKindSize uint8 = 1
)

const (
	kSectionKindZero uint8 = iota
	kSectionKindOne
)

// Types of OP_MSG requests/responses
const (
	kInsert = "insert"
	kDelete = "delete"
	kUpdate = "update"
	kFind   = "find"
	kCursor = "cursor"
	kOk     = "ok"
)

// Types of top level keys for handshaking messages
const (
	kHello             = "hello"
	kIsMaster          = "isMaster"
	kIsMasterAlternate = "ismaster"
)

// Max BSON object size in bytes
const kMaxBSONObjSize = 16000000

type State struct {
	StreamOrder []StreamOrderPair
}

type StreamOrderPair struct {
	StreamId  int32
	Processed bool
}
