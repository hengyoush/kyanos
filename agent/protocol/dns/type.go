package dns

import (
	"encoding/json"
	"fmt"
	"kyanos/agent/protocol"
)

//-----------------------------------------------------------------------------
// DNS Frame
//-----------------------------------------------------------------------------

// DNSHeader represents the DNS message header
type DNSHeader struct {
	TXID       uint16 `json:"txid"`
	Flags      uint16 `json:"flags"`
	NumQueries uint16 `json:"num_queries"`
	NumAnswers uint16 `json:"num_answers"`
	NumAuth    uint16 `json:"num_auth"`
	NumAddl    uint16 `json:"num_addl"`
}

// DNS header field offset constants
const (
	TXIDOffset       = 0
	FlagsOffset      = 2
	NumQueriesOffset = 4
	NumAnswersOffset = 6
	NumAuthOffset    = 8
	NumAddlOffset    = 10
)

// DNS header flag position and width constants
const (
	// Position constants
	QRPos     = 15
	OpcodePos = 11
	AAPos     = 10
	TCPos     = 9
	RDPos     = 8
	RAPos     = 7
	ADPos     = 5
	CDPos     = 4
	RcodePos  = 0

	// Width constants
	QRWidth     = 1
	OpcodeWidth = 4
	AAWidth     = 1
	TCWidth     = 1
	RDWidth     = 1
	RAWidth     = 1
	ADWidth     = 1
	CDWidth     = 1
	RcodeWidth  = 4
)

// ExtractDNSFlag extracts a flag from the specified position and width
func ExtractDNSFlag(flags uint16, pos, width int) uint16 {
	return (flags >> pos) & ((1 << width) - 1)
}

// DNSRecord represents a DNS resource record (usually an answer to a query)
type DNSRecord struct {
	Name  string `json:"name"`  // Name of the resource record
	CName string `json:"cname"` // CNAME of the resource record
	Type  uint16 `json:"type"`  // Type of the resource record
}

var _ protocol.ParsedMessage = &Frame{}

// Frame represents a DNS frame
type Frame struct {
	protocol.FrameBase
	Header      DNSHeader   `json:"header"`
	Records     []DNSRecord `json:"records"`
	Consumed    bool        `json:"consumed"`
	RecordsSize int64       `json:"records_size"`
	IsRequest   bool        `json:"is_req"`
}

// StreamId implements protocol.ParsedMessage.
func (f *Frame) StreamId() protocol.StreamId {
	return 0
}

func (f *Frame) IsReq() bool {
	return f.IsRequest
}

// AddRecords adds records to the frame
func (f *Frame) AddRecords(records []DNSRecord) {
	for _, r := range records {
		f.RecordsSize += int64(len(r.Name) + len(r.CName))
	}
	f.Records = append(f.Records, records...)
}

// FormatToString implements protocol.ParsedMessage.
func (f *Frame) FormatToString() string {
	recordJson, _ := json.MarshalIndent(f.Records, "", "  ")
	return fmt.Sprintf("DNS Frame: TXID=%d, Flags=%d, NumQueries=%d, NumAnswers=%d, NumAuth=%d, NumAddl=%d, Records=%v",
		f.Header.TXID, f.Header.Flags, f.Header.NumQueries, f.Header.NumAnswers, f.Header.NumAuth, f.Header.NumAddl, string(recordJson))
}
