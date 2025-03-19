package mongodb_test

import (
	"bufio"
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	. "kyanos/agent/protocol"
	"kyanos/agent/protocol/mongodb"
	. "kyanos/agent/protocol/mongodb"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var mongoDBNeedMoreHeaderData []byte = []byte{
	// message length (4 bytes)
	0x00, 0x00, 0x00, 0x0c,
	// request id
	0x82, 0xb7, 0x31, 0x44,
	// response to
	0x00, 0x00, 0x00, 0x00,
	// op code (missing a byte)
	0xdd, 0x07, 0x00,
}

var mongoDBNeedMoreData []byte = []byte{
	// message length (18 bytes)
	0x12, 0x00, 0x00, 0x00,
	// request id
	0x82, 0xb7, 0x31, 0x44,
	// response to
	0x00, 0x00, 0x00, 0x00,
	// op code
	0xdd, 0x07, 0x00, 0x00,
	// flag bits (missing byte)
	0x00,
}

var mongoDBInvalidType []byte = []byte{
	// message length (18 bytes)
	0x12, 0x00, 0x00, 0x00,
	// request id
	0x82, 0xb7, 0x31, 0x44,
	// response to
	0x00, 0x00, 0x00, 0x00,
	// op code (2010, does not exist)
	0xda, 0x07, 0x00, 0x00,
	// flag bits
	0x00, 0x00,
}

var mongoDBUnsupportedType []byte = []byte{
	// message length (18 bytes)
	0x12, 0x00, 0x00, 0x00,
	// request id
	0x82, 0xb7, 0x31, 0x44,
	// response to
	0x00, 0x00, 0x00, 0x00,
	// op code (2004, not supported in newer versions)
	0xd4, 0x07, 0x00, 0x00,
	// flag bits
	0x00, 0x00,
}

var mongoDBInvalidFlagBits []byte = []byte{
	// message length (45 bytes)
	0x2d, 0x00, 0x00, 0x00,
	// request id (917)
	0x95, 0x03, 0x00, 0x00,
	// response to (444)
	0xbc, 0x01, 0x00, 0x00,
	// op code (2013)
	0xdd, 0x07, 0x00, 0x00,
	// flag bits (bits 2, 15 are set)
	0x04, 0x80, 0x00, 0x00,
	// section 1
	0x00, 0x18, 0x00, 0x00, 0x00, 0x10, 0x6e, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x01, 0x6f, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xf0, 0x3f, 0x00,
}

var mongoDBValidFlagBitsSet []byte = []byte{
	// message length (49 bytes)
	0x31, 0x00, 0x00, 0x00,
	// request id (917)
	0x95, 0x03, 0x00, 0x00,
	// response to (444)
	0xbc, 0x01, 0x00, 0x00,
	// op code (2013)
	0xdd, 0x07, 0x00, 0x00,
	// flag bits (checksum, more to come, exhaust allowed set)
	0x03, 0x00, 0x01, 0x00,
	// section 1 (1 kind byte, 24 section body bytes)
	0x00, 0x18, 0x00, 0x00, 0x00, 0x10, 0x6e, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x01, 0x6f, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xf0, 0x3f, 0x00,
	// checksum bytes
	0x00, 0x00, 0x00, 0x00,
}

var mongoDBMissingChecksum []byte = []byte{
	// message length (161 bytes)
	0x9d, 0x00, 0x00, 0x00,
	// request id (1144108930)
	0x82, 0xb7, 0x31, 0x44,
	// response to (0)
	0x00, 0x00, 0x00, 0x00,
	// op code (2013)
	0xdd, 0x07, 0x00, 0x00,
	// flag bits (checksum set)
	0x01, 0x00, 0x00, 0x00,
	// section 1 (1 kind byte, 82 section body bytes)
	0x00, 0x52, 0x00, 0x00, 0x00, 0x02, 0x69, 0x6e, 0x73, 0x65, 0x72,
	0x74, 0x00, 0x04, 0x00, 0x00, 0x00, 0x63, 0x61, 0x72, 0x00, 0x08,
	0x6f, 0x72, 0x64, 0x65, 0x72, 0x65, 0x64, 0x00, 0x01, 0x03, 0x6c,
	0x73, 0x69, 0x64, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x05, 0x69, 0x64,
	0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x0e, 0xab, 0xf5, 0xe5, 0x45,
	0xf8, 0x42, 0x5f, 0x8c, 0xb5, 0xb4, 0x0d, 0xff, 0x94, 0x8e, 0x1c,
	0x00, 0x02, 0x24, 0x64, 0x62, 0x00, 0x06, 0x00, 0x00, 0x00, 0x6d,
	0x79, 0x64, 0x62, 0x31, 0x00, 0x00,
	// section 2 (1 kind byte, 53 section body bytes)
	0x01, 0x35, 0x00, 0x00, 0x00, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
	0x6e, 0x74, 0x73, 0x00, 0x27, 0x00, 0x00, 0x00, 0x07, 0x5f, 0x69,
	0x64, 0x00, 0x64, 0xdb, 0xd4, 0x67, 0x8f, 0x0e, 0x65, 0x5d, 0x43,
	0x14, 0xd6, 0x8a, 0x02, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x07, 0x00,
	0x00, 0x00, 0x74, 0x65, 0x73, 0x6c, 0x61, 0x34, 0x00, 0x00,
	// no checksum bytes
}

var mongoDBInvalidKindByte []byte = []byte{
	// message length (178 bytes)
	0xb2, 0x00, 0x00, 0x00,
	// request id (444)
	0xbc, 0x01, 0x00, 0x00,
	// response to (0)
	0x00, 0x00, 0x00, 0x00,
	// op code (2013)
	0xdd, 0x07, 0x00, 0x00,
	// flag bits
	0x00, 0x00, 0x00, 0x00,
	// section 1 (invalid kind byte)
	0x05, 0x9d, 0x00, 0x00, 0x00, 0x02, 0x69, 0x6e, 0x73, 0x65, 0x72,
	0x74, 0x00, 0x04, 0x00, 0x00, 0x00, 0x63, 0x61, 0x72, 0x00, 0x04,
	0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x00, 0x40,
	0x00, 0x00, 0x00, 0x03, 0x30, 0x00, 0x38, 0x00, 0x00, 0x00, 0x02,
	0x6e, 0x61, 0x6d, 0x65, 0x00, 0x18, 0x00, 0x00, 0x00, 0x70, 0x69,
	0x78, 0x69, 0x65, 0x2d, 0x63, 0x61, 0x72, 0x2d, 0x31, 0x30, 0x2d,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x37, 0x2e, 0x30, 0x00,
	0x07, 0x5f, 0x69, 0x64, 0x00, 0x64, 0xe6, 0x72, 0x9c, 0x99, 0x6d,
	0x67, 0x6b, 0xf5, 0x20, 0x9d, 0xba, 0x00, 0x00, 0x08, 0x6f, 0x72,
	0x64, 0x65, 0x72, 0x65, 0x64, 0x00, 0x01, 0x03, 0x6c, 0x73, 0x69,
	0x64, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x05, 0x69, 0x64, 0x00, 0x10,
	0x00, 0x00, 0x00, 0x04, 0xe7, 0xd7, 0x16, 0xb3, 0x75, 0xb7, 0x4c,
	0x39, 0x8b, 0x75, 0x41, 0x97, 0xc4, 0x97, 0x06, 0xd1, 0x00, 0x02,
	0x24, 0x64, 0x62, 0x00, 0x06, 0x00, 0x00, 0x00, 0x6d, 0x79, 0x64,
	0x62, 0x31, 0x00, 0x00,
}

var mongoDBInvalidSeqIdentifier []byte = []byte{
	// message length (157 bytes)
	0x9d, 0x00, 0x00, 0x00,
	// request id (1144108930)
	0x82, 0xb7, 0x31, 0x44,
	// response to (0)
	0x00, 0x00, 0x00, 0x00,
	// op code (2013)
	0xdd, 0x07, 0x00, 0x00,
	// flag bits
	0x00, 0x00, 0x00, 0x00,
	// section 1 (1 kind byte, 82 section body bytes)
	0x00, 0x52, 0x00, 0x00, 0x00, 0x02, 0x69, 0x6e, 0x73, 0x65, 0x72,
	0x74, 0x00, 0x04, 0x00, 0x00, 0x00, 0x63, 0x61, 0x72, 0x00, 0x08,
	0x6f, 0x72, 0x64, 0x65, 0x72, 0x65, 0x64, 0x00, 0x01, 0x03, 0x6c,
	0x73, 0x69, 0x64, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x05, 0x69, 0x64,
	0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x0e, 0xab, 0xf5, 0xe5, 0x45,
	0xf8, 0x42, 0x5f, 0x8c, 0xb5, 0xb4, 0x0d, 0xff, 0x94, 0x8e, 0x1c,
	0x00, 0x02, 0x24, 0x64, 0x62, 0x00, 0x06, 0x00, 0x00, 0x00, 0x6d,
	0x79, 0x64, 0x62, 0x31, 0x00, 0x00,
	// section 2 (invalid sequence identifier)
	0x01, 0x35, 0x00, 0x00, 0x00, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
	0x6e, 0x74, 0x71, 0x00, 0x27, 0x00, 0x00, 0x00, 0x07, 0x5f, 0x69,
	0x64, 0x00, 0x64, 0xdb, 0xd4, 0x67, 0x8f, 0x0e, 0x65, 0x5d, 0x43,
	0x14, 0xd6, 0x8a, 0x02, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x07, 0x00,
	0x00, 0x00, 0x74, 0x65, 0x73, 0x6c, 0x61, 0x34, 0x00, 0x00,
}

var mongoDBEmptyDocument []byte = []byte{
	// message length (79 bytes)
	0x4f, 0x00, 0x00, 0x00,
	// request id (1144108930)
	0x82, 0xb7, 0x31, 0x44,
	// response to (0)
	0x00, 0x00, 0x00, 0x00,
	// op code (2013)
	0xdd, 0x07, 0x00, 0x00,
	// flag bits
	0x00, 0x00, 0x00, 0x00,
	// section 1 (1 kind byte, 0 section body bytes)
	0x00, 0x04, 0x00, 0x00, 0x00,
	// section 2 (1 kind byte, 53 section body bytes)
	0x01, 0x35, 0x00, 0x00, 0x00, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
	0x6e, 0x74, 0x73, 0x00, 0x27, 0x00, 0x00, 0x00, 0x07, 0x5f, 0x69,
	0x64, 0x00, 0x64, 0xdb, 0xd4, 0x67, 0x8f, 0x0e, 0x65, 0x5d, 0x43,
	0x14, 0xd6, 0x8a, 0x02, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x07, 0x00,
	0x00, 0x00, 0x74, 0x65, 0x73, 0x6c, 0x61, 0x34, 0x00, 0x00,
}

var mongoDBValidRequest []byte = []byte{
	// message length (178 bytes)
	0xb2, 0x00, 0x00, 0x00,
	// request id (444)
	0xbc, 0x01, 0x00, 0x00,
	// response to (0)
	0x00, 0x00, 0x00, 0x00,
	// op code (2013)
	0xdd, 0x07, 0x00, 0x00,
	// flag bits
	0x00, 0x00, 0x00, 0x00,
	// section 1
	0x00, 0x9d, 0x00, 0x00, 0x00, 0x02, 0x69, 0x6e, 0x73, 0x65, 0x72,
	0x74, 0x00, 0x04, 0x00, 0x00, 0x00, 0x63, 0x61, 0x72, 0x00, 0x04,
	0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x00, 0x40,
	0x00, 0x00, 0x00, 0x03, 0x30, 0x00, 0x38, 0x00, 0x00, 0x00, 0x02,
	0x6e, 0x61, 0x6d, 0x65, 0x00, 0x18, 0x00, 0x00, 0x00, 0x70, 0x69,
	0x78, 0x69, 0x65, 0x2d, 0x63, 0x61, 0x72, 0x2d, 0x31, 0x30, 0x2d,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x37, 0x2e, 0x30, 0x00,
	0x07, 0x5f, 0x69, 0x64, 0x00, 0x64, 0xe6, 0x72, 0x9c, 0x99, 0x6d,
	0x67, 0x6b, 0xf5, 0x20, 0x9d, 0xba, 0x00, 0x00, 0x08, 0x6f, 0x72,
	0x64, 0x65, 0x72, 0x65, 0x64, 0x00, 0x01, 0x03, 0x6c, 0x73, 0x69,
	0x64, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x05, 0x69, 0x64, 0x00, 0x10,
	0x00, 0x00, 0x00, 0x04, 0xe7, 0xd7, 0x16, 0xb3, 0x75, 0xb7, 0x4c,
	0x39, 0x8b, 0x75, 0x41, 0x97, 0xc4, 0x97, 0x06, 0xd1, 0x00, 0x02,
	0x24, 0x64, 0x62, 0x00, 0x06, 0x00, 0x00, 0x00, 0x6d, 0x79, 0x64,
	0x62, 0x31, 0x00, 0x00,
}

var mongoDBValidResponse []byte = []byte{
	// message length (45 bytes)
	0x2d, 0x00, 0x00, 0x00,
	// request id (917)
	0x95, 0x03, 0x00, 0x00,
	// response to (444)
	0xbc, 0x01, 0x00, 0x00,
	// op code (2013)
	0xdd, 0x07, 0x00, 0x00,
	// flag bits
	0x00, 0x00, 0x00, 0x00,
	// section 1
	0x00, 0x18, 0x00, 0x00, 0x00, 0x10, 0x6e, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x01, 0x6f, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xf0, 0x3f, 0x00,
}

var mongoDBValidRequestTwoSections []byte = []byte{
	// message length (157 bytes)
	0x9d, 0x00, 0x00, 0x00,
	// request id (1144108930)
	0x82, 0xb7, 0x31, 0x44,
	// response to (0)
	0x00, 0x00, 0x00, 0x00,
	// op code (2013)
	0xdd, 0x07, 0x00, 0x00,
	// flag bits
	0x00, 0x00, 0x00, 0x00,
	// section 1 (1 kind byte, 82 section body bytes)
	0x00, 0x52, 0x00, 0x00, 0x00, 0x02, 0x69, 0x6e, 0x73, 0x65, 0x72,
	0x74, 0x00, 0x04, 0x00, 0x00, 0x00, 0x63, 0x61, 0x72, 0x00, 0x08,
	0x6f, 0x72, 0x64, 0x65, 0x72, 0x65, 0x64, 0x00, 0x01, 0x03, 0x6c,
	0x73, 0x69, 0x64, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x05, 0x69, 0x64,
	0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x0e, 0xab, 0xf5, 0xe5, 0x45,
	0xf8, 0x42, 0x5f, 0x8c, 0xb5, 0xb4, 0x0d, 0xff, 0x94, 0x8e, 0x1c,
	0x00, 0x02, 0x24, 0x64, 0x62, 0x00, 0x06, 0x00, 0x00, 0x00, 0x6d,
	0x79, 0x64, 0x62, 0x31, 0x00, 0x00,
	// section 2 (1 kind byte, 53 section body bytes)
	0x01, 0x35, 0x00, 0x00, 0x00, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
	0x6e, 0x74, 0x73, 0x00, 0x27, 0x00, 0x00, 0x00, 0x07, 0x5f, 0x69,
	0x64, 0x00, 0x64, 0xdb, 0xd4, 0x67, 0x8f, 0x0e, 0x65, 0x5d, 0x43,
	0x14, 0xd6, 0x8a, 0x02, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x07, 0x00,
	0x00, 0x00, 0x74, 0x65, 0x73, 0x6c, 0x61, 0x34, 0x00, 0x00,
}

var mongoDBValidResponseTwoSections []byte = []byte{
	// message length (45 bytes)
	0x2d, 0x00, 0x00, 0x00,
	// request id (444)
	0xbc, 0x01, 0x00, 0x00,
	// response to (1144108930)
	0x82, 0xb7, 0x31, 0x44,
	// op code (2013)
	0xdd, 0x07, 0x00, 0x00,
	// flag bits
	0x00, 0x00, 0x00, 0x00,
	// section 1 (1 kind byte, 24 section body bytes)
	0x00, 0x18, 0x00, 0x00, 0x00, 0x10, 0x6e, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x01, 0x6f, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xf0, 0x3f, 0x00,
}

var mongoDBValidRequestAndInvalidRequest []byte = []byte{
	// valid frame
	// message length (45 bytes)
	0x2d, 0x00, 0x00, 0x00,
	// request id (917)
	0x95, 0x03, 0x00, 0x00,
	// response to (444)
	0xbc, 0x01, 0x00, 0x00,
	// op code (2013)
	0xdd, 0x07, 0x00, 0x00,
	// flag bits
	0x00, 0x00, 0x00, 0x00,
	// section 1
	0x00, 0x18, 0x00, 0x00, 0x00, 0x10, 0x6e, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x01, 0x6f, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xf0, 0x3f, 0x00,

	// invalid frame
	// message length (18 bytes)
	0x12, 0x00, 0x00, 0x00,
	// request id (444)
	0xbc, 0x01, 0x00, 0x00,
	// response to (0)
	0x00, 0x00, 0x00, 0x00,
	// flag bits
	0xFF, 0xFF, 0xFF, 0xFF,
	// section data
	0x00, 0x00,
}

func TestXxx(t *testing.T) {
	reader := strings.NewReader("GET /abc HTTP/1.1\r\nHost: www.baidu.com\r\n\r\nGET /abc2 HTTP/1.1\r\nHost: www.baidu.com\r\n\r\n")
	x := bufio.NewReader(reader)
	http.ReadRequest(x)
	_, err := http.ReadRequest(x)
	ty := reflect.ValueOf(*x)
	f := ty.FieldByName("r")
	fmt.Printf("%d %d %v \n%v\n", reader.Size(), reader.Len(), f.Int(), reader)
	fmt.Println("Hello, 世界")
	fmt.Println(err)
}

func TestParseFrameWhenNeedsMoreHeaderData(t *testing.T) {
	MongoDBStreamParser := mongodb.NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBNeedMoreHeaderData)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Request)
	assert.True(t, parseResult.ParseState == protocol.NeedsMoreData)
}

func TestParseFrameWhenNeedsMoreData(t *testing.T) {
	MongoDBStreamParser := mongodb.NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBNeedMoreData)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Request)
	assert.True(t, parseResult.ParseState == protocol.NeedsMoreData)
}

func TestParseFrameWhenNotValidType(t *testing.T) {
	MongoDBStreamParser := mongodb.NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBInvalidType)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Request)
	assert.True(t, parseResult.ParseState == protocol.Invalid)
}

func TestParseFrameWhenUnsupportedType(t *testing.T) {
	MongoDBStreamParser := mongodb.NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBUnsupportedType)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Request)
	assert.True(t, parseResult.ParseState == protocol.Ignore)
}

func TestParseFrameValidFlagBitsSet(t *testing.T) {
	MongoDBStreamParser := NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBValidFlagBitsSet)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Request)
	assert.True(t, parseResult.ParseState == protocol.Success)
	mongoDBFrame := parseResult.ParsedMessages[0].(*MongoDBFrame)
	assert.True(t, mongoDBFrame.ChecksumPresent == true)
	assert.True(t, mongoDBFrame.MoreToCome == true)
	assert.True(t, mongoDBFrame.ExhaustAllowed == true)
}

func TestParseFrameInvalidChecksum(t *testing.T) {
	MongoDBStreamParser := NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBMissingChecksum)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Request)
	assert.True(t, parseResult.ParseState == protocol.Invalid)
	mongoDBFrame := parseResult.ParsedMessages[0].(*MongoDBFrame)
	assert.True(t, mongoDBFrame.ChecksumPresent == true)
}

func TestParseFrameInvalidKindByte(t *testing.T) {
	MongoDBStreamParser := NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBInvalidKindByte)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Request)
	assert.True(t, parseResult.ParseState == protocol.Invalid)
}

func TestParseFrameInvalidSeqIdentifier(t *testing.T) {
	MongoDBStreamParser := NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBInvalidSeqIdentifier)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Request)
	assert.True(t, parseResult.ParseState == protocol.Invalid)
}

func TestParseFrameEmptyDocument(t *testing.T) {
	MongoDBStreamParser := NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBEmptyDocument)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Request)
	assert.True(t, parseResult.ParseState == protocol.Success)
	mongoDBFrame := parseResult.ParsedMessages[0].(*MongoDBFrame)
	assert.True(t, mongoDBFrame.Sections[0].Kind() == 0)
	assert.True(t, mongoDBFrame.Sections[0].Length() == 4)
	assert.True(t, len(mongoDBFrame.Sections[0].Documents[0]) == 0)
	assert.True(t, mongoDBFrame.Sections[1].Kind() == 1)
	assert.True(t, mongoDBFrame.Sections[1].Length() == 53)
	assert.True(t, len(mongoDBFrame.Sections[1].Documents[0]) == 59)

}

func TestParseFrameValidRequest(t *testing.T) {
	MongoDBStreamParser := NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBValidRequest)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Request)
	assert.True(t, parseResult.ParseState == protocol.Success)
	mongoDBFrame := parseResult.ParsedMessages[0].(*MongoDBFrame)
	assert.True(t, mongoDBFrame.Length == 178)
	assert.True(t, mongoDBFrame.RequestId == 444)
	assert.True(t, mongoDBFrame.ResponseTo == 0)
	assert.True(t, mongoDBFrame.OpCode == 2013)
	assert.True(t, mongoDBFrame.Sections[0].Kind() == 0)
	assert.True(t, mongoDBFrame.Sections[0].Length() == 157)
	assert.True(t, mongoDBFrame.OpMsgType == "insert")
}

func TestParseFrameValidResponse(t *testing.T) {
	MongoDBStreamParser := NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBValidResponse)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Response)
	assert.True(t, parseResult.ParseState == protocol.Success)
	mongoDBFrame := parseResult.ParsedMessages[0].(*MongoDBFrame)
	assert.True(t, mongoDBFrame.Length == 45)
	assert.True(t, mongoDBFrame.RequestId == 917)
	assert.True(t, mongoDBFrame.ResponseTo == 444)
	assert.True(t, mongoDBFrame.OpCode == 2013)
	assert.True(t, mongoDBFrame.Sections[0].Kind() == 0)
	assert.True(t, mongoDBFrame.Sections[0].Length() == 24)
	assert.True(t, mongoDBFrame.OpMsgType == "ok: {$numberDouble: 1.0}")
}

func TestParseFrameValidRequestTwoSections(t *testing.T) {
	MongoDBStreamParser := NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBValidRequestTwoSections)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Request)
	assert.True(t, parseResult.ParseState == protocol.Success)
	mongoDBFrame := parseResult.ParsedMessages[0].(*MongoDBFrame)
	assert.True(t, mongoDBFrame.Length == 157)
	assert.True(t, mongoDBFrame.RequestId == 1144108930)
	assert.True(t, mongoDBFrame.ResponseTo == 0)
	assert.True(t, mongoDBFrame.OpCode == 2013)
	assert.True(t, mongoDBFrame.Sections[0].Kind() == 0)
	assert.True(t, mongoDBFrame.Sections[0].Length() == 82)
	assert.True(t, mongoDBFrame.OpMsgType == "insert")
	assert.True(t, mongoDBFrame.Sections[1].Kind() == 1)
	assert.True(t, mongoDBFrame.Sections[1].Length() == 53)
}

func TestParseFrameValidResponseTwoSections(t *testing.T) {
	MongoDBStreamParser := NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBValidResponseTwoSections)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Response)
	assert.True(t, parseResult.ParseState == protocol.Success)
	mongoDBFrame := parseResult.ParsedMessages[0].(*MongoDBFrame)
	assert.True(t, mongoDBFrame.Length == 45)
	assert.True(t, mongoDBFrame.RequestId == 444)
	assert.True(t, mongoDBFrame.ResponseTo == 1144108930)
	assert.True(t, mongoDBFrame.OpCode == 2013)
	assert.True(t, mongoDBFrame.Sections[0].Kind() == 0)
	assert.True(t, mongoDBFrame.Sections[0].Length() == 24)
	assert.True(t, mongoDBFrame.OpMsgType == "ok: {$numberDouble: 1.0}")
}

func TestParseValidFrameAndInvalidFrame(t *testing.T) {
	MongoDBStreamParser := NewMongoDBStreamParser()
	streamBuffer := buffer.New(10000)

	produceFrameView := []byte(mongoDBValidRequestAndInvalidRequest)
	streamBuffer.Add(1, produceFrameView, uint64(time.Now().Nanosecond()))

	parseResult := MongoDBStreamParser.ParseStream(streamBuffer, protocol.Request)
	assert.True(t, parseResult.ParseState == protocol.Success)
	mongoDBFrame := parseResult.ParsedMessages[0].(*MongoDBFrame)
	assert.True(t, mongoDBFrame.Length == 45)
	assert.True(t, mongoDBFrame.RequestId == 917)
	assert.True(t, mongoDBFrame.ResponseTo == 444)
	assert.True(t, mongoDBFrame.OpCode == 2013)
	assert.True(t, mongoDBFrame.Sections[0].Kind() == 0)
	assert.True(t, mongoDBFrame.Sections[0].Length() == 24)
	assert.True(t, mongoDBFrame.OpMsgType == "ok: {$numberDouble: 1.0}")
}

func TestValidateStateOrderFromFrames(t *testing.T) {
	MongoDBStreamParser := NewMongoDBStreamParser()
	streamOrderPairs := []StreamOrderPair{
		{StreamId: 917, Processed: false},
	}

	streamBuffer1 := buffer.New(10000)
	produceFrameView1 := []byte(mongoDBValidFlagBitsSet)
	streamBuffer1.Add(1, produceFrameView1, uint64(time.Now().Nanosecond()))
	parseResult1 := MongoDBStreamParser.ParseStream(streamBuffer1, protocol.Request)

	mongoDBFrame1 := parseResult1.ParsedMessages[0].(*MongoDBFrame)
	assert.True(t, mongoDBFrame1.RequestId == 917)
	assert.True(t, slicesEqual(MongoDBStreamParser.StreamOrder, streamOrderPairs))
	assert.True(t, parseResult1.ParseState == protocol.Success)

	newPair2 := StreamOrderPair{StreamId: 444, Processed: false}
	streamOrderPairs = append(streamOrderPairs, newPair2)

	streamBuffer2 := buffer.New(10000)
	produceFrameView2 := []byte(mongoDBValidRequest)
	streamBuffer2.Add(1, produceFrameView2, uint64(time.Now().Nanosecond()))
	parseResult2 := MongoDBStreamParser.ParseStream(streamBuffer2, protocol.Request)
	mongoDBFrame2 := parseResult2.ParsedMessages[0].(*MongoDBFrame)
	assert.True(t, mongoDBFrame2.RequestId == 444)
	assert.True(t, slicesEqual(MongoDBStreamParser.StreamOrder, streamOrderPairs))
	assert.True(t, parseResult2.ParseState == protocol.Success)

	newPair3 := StreamOrderPair{StreamId: 1144108930, Processed: false}
	streamOrderPairs = append(streamOrderPairs, newPair3)

	streamBuffer3 := buffer.New(10000)
	produceFrameView3 := []byte(mongoDBValidRequestTwoSections)
	streamBuffer3.Add(1, produceFrameView3, uint64(time.Now().Nanosecond()))
	parseResult3 := MongoDBStreamParser.ParseStream(streamBuffer3, protocol.Request)
	mongoDBFrame3 := parseResult3.ParsedMessages[0].(*MongoDBFrame)
	assert.True(t, mongoDBFrame3.RequestId == 1144108930)
	assert.True(t, slicesEqual(MongoDBStreamParser.StreamOrder, streamOrderPairs))
	assert.True(t, parseResult3.ParseState == protocol.Success)
}

func slicesEqual(a, b []StreamOrderPair) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func createMongoDBFrame(ts_ns uint64, requestID int32, responseTo int32, moreToCome bool, doc string, isHandshake bool) *MongoDBFrame {

	var sections []Section
	var section Section
	section.Documents = append(section.Documents, doc)
	sections = append(sections, section)

	mongoDBFrame := MongoDBFrame{
		FrameBase: NewFrameBase(ts_ns, 0, 0),
		//length:     length,
		RequestId:   requestID,
		ResponseTo:  responseTo,
		MoreToCome:  moreToCome,
		IsHandshake: isHandshake,
		Sections:    sections,
	}

	return &mongoDBFrame
}

func TestVerifyStitchingWithReusedStreams(t *testing.T) {
	reqs := make(map[StreamId]*ParsedMessageQueue)
	resps := make(map[StreamId]*ParsedMessageQueue)
	reqs[1] = &ParsedMessageQueue{}
	reqs[3] = &ParsedMessageQueue{}
	reqs[5] = &ParsedMessageQueue{}
	*reqs[1] = append(*reqs[1], createMongoDBFrame(0, 1, 0, false, "", false))
	*reqs[3] = append(*reqs[3], createMongoDBFrame(2, 3, 0, false, "", false))
	*reqs[5] = append(*reqs[5], createMongoDBFrame(4, 5, 0, false, "", false))

	*reqs[1] = append(*reqs[1], createMongoDBFrame(6, 1, 0, false, "", false))
	*reqs[3] = append(*reqs[3], createMongoDBFrame(8, 3, 0, false, "", false))
	*reqs[5] = append(*reqs[5], createMongoDBFrame(10, 5, 0, false, "", false))
	*reqs[5] = append(*reqs[5], createMongoDBFrame(12, 5, 0, false, "", false))

	resps[1] = &ParsedMessageQueue{}
	resps[3] = &ParsedMessageQueue{}
	resps[5] = &ParsedMessageQueue{}
	*resps[1] = append(*resps[1], createMongoDBFrame(1, 2, 1, false, "", false))
	*resps[3] = append(*resps[3], createMongoDBFrame(3, 4, 3, false, "", false))
	*resps[5] = append(*resps[5], createMongoDBFrame(5, 6, 5, false, "", false))

	*resps[1] = append(*resps[1], createMongoDBFrame(7, 8, 1, false, "", false))
	*resps[3] = append(*resps[3], createMongoDBFrame(9, 10, 3, false, "", false))
	*resps[3] = append(*resps[3], createMongoDBFrame(13, 13, 3, false, "", false))
	*resps[5] = append(*resps[5], createMongoDBFrame(11, 12, 5, false, "", false))

	MongoDBStreamParser := NewMongoDBStreamParser()
	streamOrderPairs := []StreamOrderPair{}
	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: 1, Processed: false})
	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: 3, Processed: false})
	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: 5, Processed: false})
	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: 1, Processed: false})
	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: 3, Processed: false})
	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: 5, Processed: false})
	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: 5, Processed: false})

	MongoDBStreamParser.StreamOrder = streamOrderPairs
	records := MongoDBStreamParser.Match(reqs, resps)
	assert.True(t, len(records) == 6)
	assert.True(t, records[0].Req.TimestampNs() == 0)
	assert.True(t, records[0].Resp.TimestampNs() == 1)
	assert.True(t, records[5].Req.TimestampNs() == 10)
	assert.True(t, records[5].Resp.TimestampNs() == 11)

	assert.True(t, len(reqs) == 1)
	assert.True(t, len(resps) == 0)
	assert.True(t, len(MongoDBStreamParser.StreamOrder) == 0)
}

func TestVerifyOnetoOneStitching(t *testing.T) {
	reqs := make(map[StreamId]*ParsedMessageQueue)
	resps := make(map[StreamId]*ParsedMessageQueue)

	for i := 1; i <= 15; i += 2 {
		reqs[StreamId(i)] = &ParsedMessageQueue{}
		resps[StreamId(i)] = &ParsedMessageQueue{}
	}
	*reqs[1] = append(*reqs[1], createMongoDBFrame(0, 1, 0, false, "", false))
	*reqs[3] = append(*reqs[3], createMongoDBFrame(2, 3, 0, false, "", false))
	*reqs[5] = append(*reqs[5], createMongoDBFrame(4, 5, 0, false, "", false))
	*reqs[7] = append(*reqs[7], createMongoDBFrame(6, 7, 0, false, "", false))
	*reqs[9] = append(*reqs[9], createMongoDBFrame(8, 9, 0, false, "", false))
	*reqs[11] = append(*reqs[11], createMongoDBFrame(10, 11, 0, false, "", false))
	*reqs[13] = append(*reqs[13], createMongoDBFrame(12, 13, 0, false, "", false))
	*reqs[15] = append(*reqs[15], createMongoDBFrame(14, 15, 0, false, "", false))

	*resps[1] = append(*resps[1], createMongoDBFrame(1, 2, 1, false, "", false))
	*resps[3] = append(*resps[3], createMongoDBFrame(3, 4, 3, false, "", false))
	*resps[5] = append(*resps[5], createMongoDBFrame(5, 6, 5, false, "", false))
	*resps[7] = append(*resps[7], createMongoDBFrame(7, 8, 7, false, "", false))
	*resps[9] = append(*resps[9], createMongoDBFrame(9, 10, 9, false, "", false))
	*resps[11] = append(*resps[11], createMongoDBFrame(11, 12, 11, false, "", false))
	*resps[13] = append(*resps[13], createMongoDBFrame(13, 14, 13, false, "", false))
	*resps[15] = append(*resps[15], createMongoDBFrame(15, 16, 15, false, "", false))

	MongoDBStreamParser := NewMongoDBStreamParser()
	streamOrderPairs := []StreamOrderPair{}
	for i := 1; i <= 15; i += 2 {
		streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: int32(i), Processed: false})
	}

	MongoDBStreamParser.StreamOrder = streamOrderPairs
	records := MongoDBStreamParser.Match(reqs, resps)
	assert.True(t, len(records) == 8)
	assert.True(t, len(reqs) == 0)
	assert.True(t, len(resps) == 0)
	assert.True(t, len(MongoDBStreamParser.StreamOrder) == 0)
}

func TestVerifyOnetoNStitching(t *testing.T) {
	reqs := make(map[StreamId]*ParsedMessageQueue)
	resps := make(map[StreamId]*ParsedMessageQueue)

	for i := 1; i <= 17; i += 2 {
		reqs[StreamId(i)] = &ParsedMessageQueue{}
		resps[StreamId(i)] = &ParsedMessageQueue{}
	}
	delete(reqs, 7)
	resps[6] = &ParsedMessageQueue{}

	*reqs[1] = append(*reqs[1], createMongoDBFrame(0, 1, 0, false, "", false))
	*reqs[3] = append(*reqs[3], createMongoDBFrame(2, 3, 0, false, "", false))
	*reqs[5] = append(*reqs[5], createMongoDBFrame(4, 5, 0, false, "request frame body", false))
	*reqs[9] = append(*reqs[9], createMongoDBFrame(8, 9, 0, false, "", false))
	*reqs[11] = append(*reqs[11], createMongoDBFrame(10, 11, 0, false, "", false))
	*reqs[13] = append(*reqs[13], createMongoDBFrame(12, 13, 0, false, "", false))
	*reqs[15] = append(*reqs[15], createMongoDBFrame(14, 15, 0, false, "", false))
	*reqs[17] = append(*reqs[17], createMongoDBFrame(16, 17, 0, false, "", false))

	*resps[1] = append(*resps[1], createMongoDBFrame(1, 2, 1, false, "", false))
	*resps[3] = append(*resps[3], createMongoDBFrame(3, 4, 3, false, "", false))
	*resps[5] = append(*resps[5], createMongoDBFrame(5, 6, 5, true, "response", false))
	*resps[6] = append(*resps[6], createMongoDBFrame(6, 7, 6, true, "frame", false))
	*resps[7] = append(*resps[7], createMongoDBFrame(7, 8, 7, false, "body", false))
	*resps[9] = append(*resps[9], createMongoDBFrame(9, 10, 9, false, "", false))
	*resps[11] = append(*resps[11], createMongoDBFrame(11, 12, 11, false, "", false))
	*resps[13] = append(*resps[13], createMongoDBFrame(13, 14, 13, false, "", false))
	*resps[15] = append(*resps[15], createMongoDBFrame(15, 16, 15, false, "", false))
	*resps[17] = append(*resps[17], createMongoDBFrame(17, 18, 17, false, "", false))

	MongoDBStreamParser := NewMongoDBStreamParser()
	streamOrderPairs := []StreamOrderPair{}
	for i := 1; i <= 17; i += 2 {
		if i != 7 {
			streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: int32(i), Processed: false})
		}
	}

	MongoDBStreamParser.StreamOrder = streamOrderPairs
	records := MongoDBStreamParser.Match(reqs, resps)
	assert.True(t, records[2].Req.(*MongoDBFrame).Frame_body == "request frame body ")
	assert.True(t, records[2].Resp.(*MongoDBFrame).Frame_body == "response frame body ")

	assert.True(t, len(records) == 8)
	assert.True(t, len(reqs) == 0)
	assert.True(t, len(resps) == 0)
	assert.True(t, len(MongoDBStreamParser.StreamOrder) == 0)
}

func TestUnmatchedResponsesAreHandled(t *testing.T) {
	reqs := make(map[StreamId]*ParsedMessageQueue)
	resps := make(map[StreamId]*ParsedMessageQueue)

	reqs[2] = &ParsedMessageQueue{}
	*reqs[2] = append(*reqs[2], createMongoDBFrame(1, 2, 0, false, "", false))

	resps[2] = &ParsedMessageQueue{}
	resps[10] = &ParsedMessageQueue{}
	*resps[10] = append(*resps[10], createMongoDBFrame(0, 1, 10, false, "", false))
	*resps[2] = append(*resps[2], createMongoDBFrame(2, 3, 2, false, "", false))

	MongoDBStreamParser := NewMongoDBStreamParser()
	streamOrderPairs := []StreamOrderPair{}

	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: int32(2), Processed: false})

	MongoDBStreamParser.StreamOrder = streamOrderPairs
	records := MongoDBStreamParser.Match(reqs, resps)
	assert.True(t, records[0].Req.(*MongoDBFrame).RequestId == 2)
	assert.True(t, records[0].Resp.(*MongoDBFrame).ResponseTo == 2)

	assert.True(t, len(records) == 1)
	assert.True(t, len(reqs) == 0)
	assert.True(t, len(resps) == 0)
	assert.True(t, len(MongoDBStreamParser.StreamOrder) == 0)
}

func TestUnmatchedRequestsAreNotCleanedUp(t *testing.T) {
	reqs := make(map[StreamId]*ParsedMessageQueue)
	resps := make(map[StreamId]*ParsedMessageQueue)

	reqs[1] = &ParsedMessageQueue{}
	reqs[2] = &ParsedMessageQueue{}
	reqs[4] = &ParsedMessageQueue{}
	*reqs[1] = append(*reqs[1], createMongoDBFrame(0, 1, 0, false, "", false))
	*reqs[2] = append(*reqs[2], createMongoDBFrame(1, 2, 0, false, "", false))
	*reqs[4] = append(*reqs[4], createMongoDBFrame(3, 4, 0, false, "", false))

	resps[2] = &ParsedMessageQueue{}
	resps[4] = &ParsedMessageQueue{}
	*resps[2] = append(*resps[2], createMongoDBFrame(2, 3, 2, false, "", false))
	*resps[4] = append(*resps[4], createMongoDBFrame(4, 5, 4, false, "", false))

	MongoDBStreamParser := NewMongoDBStreamParser()
	streamOrderPairs := []StreamOrderPair{}

	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: int32(1), Processed: false})
	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: int32(2), Processed: false})
	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: int32(4), Processed: false})

	MongoDBStreamParser.StreamOrder = streamOrderPairs
	records := MongoDBStreamParser.Match(reqs, resps)
	assert.True(t, records[0].Req.(*MongoDBFrame).RequestId == 2)
	assert.True(t, records[1].Req.(*MongoDBFrame).RequestId == 4)

	assert.True(t, len(records) == 2)
	assert.True(t, len(resps) == 0)
	assert.True(t, len(MongoDBStreamParser.StreamOrder) == 1)
}

func TestMissingHeadFrameInNResponses(t *testing.T) {
	reqs := make(map[StreamId]*ParsedMessageQueue)
	resps := make(map[StreamId]*ParsedMessageQueue)

	reqs[1] = &ParsedMessageQueue{}
	reqs[6] = &ParsedMessageQueue{}
	*reqs[1] = append(*reqs[1], createMongoDBFrame(0, 1, 0, false, "", false))
	*reqs[6] = append(*reqs[6], createMongoDBFrame(5, 6, 0, false, "", false))

	resps[2] = &ParsedMessageQueue{}
	resps[3] = &ParsedMessageQueue{}
	resps[6] = &ParsedMessageQueue{}
	*resps[2] = append(*resps[2], createMongoDBFrame(2, 3, 2, false, "", false))
	*resps[3] = append(*resps[3], createMongoDBFrame(3, 4, 3, false, "", false))
	*resps[6] = append(*resps[6], createMongoDBFrame(6, 7, 6, false, "", false))

	MongoDBStreamParser := NewMongoDBStreamParser()
	streamOrderPairs := []StreamOrderPair{}

	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: int32(1), Processed: false})
	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: int32(6), Processed: false})

	MongoDBStreamParser.StreamOrder = streamOrderPairs
	records := MongoDBStreamParser.Match(reqs, resps)

	assert.True(t, len(records) == 1)
	assert.True(t, len(reqs) == 1)
	assert.True(t, len(MongoDBStreamParser.StreamOrder) == 1)
}

func TestMissingFrameInNResponses(t *testing.T) {
	reqs := make(map[StreamId]*ParsedMessageQueue)
	resps := make(map[StreamId]*ParsedMessageQueue)

	reqs[1] = &ParsedMessageQueue{}
	reqs[6] = &ParsedMessageQueue{}
	*reqs[1] = append(*reqs[1], createMongoDBFrame(0, 1, 0, false, "", false))
	*reqs[6] = append(*reqs[6], createMongoDBFrame(5, 6, 0, false, "", false))

	resps[1] = &ParsedMessageQueue{}
	resps[2] = &ParsedMessageQueue{}
	resps[4] = &ParsedMessageQueue{}
	resps[6] = &ParsedMessageQueue{}
	*resps[1] = append(*resps[1], createMongoDBFrame(1, 2, 1, true, "frame 1", false))
	*resps[2] = append(*resps[2], createMongoDBFrame(2, 3, 2, true, "frame 2", false))
	*resps[4] = append(*resps[4], createMongoDBFrame(4, 5, 4, false, "frame 4", false))
	*resps[6] = append(*resps[6], createMongoDBFrame(6, 7, 6, false, "", false))

	MongoDBStreamParser := NewMongoDBStreamParser()
	streamOrderPairs := []StreamOrderPair{}

	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: int32(1), Processed: false})
	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: int32(6), Processed: false})

	MongoDBStreamParser.StreamOrder = streamOrderPairs
	records := MongoDBStreamParser.Match(reqs, resps)

	assert.True(t, records[0].Resp.(*MongoDBFrame).Frame_body == "frame 1 frame 2 ")
	assert.True(t, len(records) == 2)
	assert.True(t, len(reqs) == 0)
	assert.True(t, len(resps) == 0)
	assert.True(t, len(MongoDBStreamParser.StreamOrder) == 0)
}

func TestMissingTailFrameInNResponses(t *testing.T) {
	reqs := make(map[StreamId]*ParsedMessageQueue)
	resps := make(map[StreamId]*ParsedMessageQueue)

	reqs[1] = &ParsedMessageQueue{}
	reqs[6] = &ParsedMessageQueue{}
	*reqs[1] = append(*reqs[1], createMongoDBFrame(0, 1, 0, false, "", false))
	*reqs[6] = append(*reqs[6], createMongoDBFrame(5, 6, 0, false, "", false))

	resps[1] = &ParsedMessageQueue{}
	resps[2] = &ParsedMessageQueue{}
	resps[3] = &ParsedMessageQueue{}
	resps[6] = &ParsedMessageQueue{}
	*resps[1] = append(*resps[1], createMongoDBFrame(1, 2, 1, true, "frame 1", false))
	*resps[2] = append(*resps[2], createMongoDBFrame(2, 3, 2, true, "frame 2", false))
	*resps[3] = append(*resps[3], createMongoDBFrame(3, 4, 3, true, "frame 3", false))
	*resps[6] = append(*resps[6], createMongoDBFrame(6, 7, 6, false, "", false))

	MongoDBStreamParser := NewMongoDBStreamParser()
	streamOrderPairs := []StreamOrderPair{}

	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: int32(1), Processed: false})
	streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: int32(6), Processed: false})

	MongoDBStreamParser.StreamOrder = streamOrderPairs
	records := MongoDBStreamParser.Match(reqs, resps)

	assert.True(t, records[0].Resp.(*MongoDBFrame).Frame_body == "frame 1 frame 2 frame 3 ")
	assert.True(t, len(records) == 2)
	assert.True(t, len(reqs) == 0)
	assert.True(t, len(resps) == 0)
	assert.True(t, len(MongoDBStreamParser.StreamOrder) == 0)
}

func TestVerifyHandshakingMessages(t *testing.T) {
	reqs := make(map[StreamId]*ParsedMessageQueue)
	resps := make(map[StreamId]*ParsedMessageQueue)

	for i := 1; i <= 7; i += 2 {
		reqs[StreamId(i)] = &ParsedMessageQueue{}
		resps[StreamId(i)] = &ParsedMessageQueue{}
	}

	*reqs[1] = append(*reqs[1], createMongoDBFrame(0, 1, 0, false, "", false))
	*reqs[3] = append(*reqs[3], createMongoDBFrame(2, 3, 0, false, "", false))
	*reqs[5] = append(*reqs[5], createMongoDBFrame(4, 5, 0, false, "", true))
	*reqs[7] = append(*reqs[7], createMongoDBFrame(6, 7, 0, false, "", false))

	*resps[1] = append(*resps[1], createMongoDBFrame(1, 2, 1, false, "", false))
	*resps[3] = append(*resps[3], createMongoDBFrame(3, 4, 3, false, "", false))
	*resps[5] = append(*resps[5], createMongoDBFrame(5, 6, 5, false, "", true))
	*resps[7] = append(*resps[7], createMongoDBFrame(7, 8, 7, false, "", false))

	MongoDBStreamParser := NewMongoDBStreamParser()
	streamOrderPairs := []StreamOrderPair{}
	for i := 1; i <= 7; i += 2 {
		streamOrderPairs = append(streamOrderPairs, StreamOrderPair{StreamId: int32(i), Processed: false})
	}

	MongoDBStreamParser.StreamOrder = streamOrderPairs
	records := MongoDBStreamParser.Match(reqs, resps)

	assert.True(t, len(records) == 3)
	// There should be 3 records in vector since the stitcher ignores handshaking frames but will
	// still consume them successfully.
	assert.True(t, len(reqs) == 0)
	assert.True(t, len(resps) == 0)
	assert.True(t, len(MongoDBStreamParser.StreamOrder) == 0)
}
