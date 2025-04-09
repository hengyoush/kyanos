package dns

import (
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	"kyanos/bpf"
	"kyanos/common"
	"unsafe"

	"github.com/miekg/dns"
)

var _ protocol.ProtocolStreamParser = &DnsStreamParser{}

type DnsStreamParser struct {
}

func NewDnsStreamParser() *DnsStreamParser {
	return &DnsStreamParser{}
}

func init() {
	protocol.ParsersMap[bpf.AgentTrafficProtocolTKProtocolDNS] = func() protocol.ProtocolStreamParser {
		return &DnsStreamParser{}
	}
}

func (k *DnsStreamParser) ParseStream(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType) protocol.ParseResult {
	buf := streamBuffer.Head().Buffer()
	msg := new(dns.Msg)
	err := msg.Unpack(buf)
	if err != nil {
		common.ProtocolParserLog.Debugf("Failed to unpack DNS message: %v", err)
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}

	if len(buf) < int(unsafe.Sizeof(DNSHeader{})) {
		return protocol.ParseResult{
			ParseState: protocol.NeedsMoreData,
		}
	}

	binaryDecoder := protocol.NewBinaryDecoder(buf)
	frame := Frame{}
	frame.Header.TXID, err = protocol.ExtractBEInt[uint16](binaryDecoder)
	if err != nil {
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	frame.Header.Flags, err = protocol.ExtractBEInt[uint16](binaryDecoder)
	if err != nil {
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	frame.Header.NumQueries, err = protocol.ExtractBEInt[uint16](binaryDecoder)
	if err != nil {
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	frame.Header.NumAnswers, err = protocol.ExtractBEInt[uint16](binaryDecoder)
	if err != nil {
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	frame.Header.NumAuth, err = protocol.ExtractBEInt[uint16](binaryDecoder)
	if err != nil {
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	frame.Header.NumAddl, err = protocol.ExtractBEInt[uint16](binaryDecoder)
	if err != nil {
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	for _, question := range msg.Question {
		frame.AddRecords([]DNSRecord{
			{
				Name: question.Name,
				Type: question.Qtype,
			},
		})
	}
	// msg.
	for _, answer := range msg.Answer {
		dnsRecord := DNSRecord{}
		dnsRecord.Name = answer.Header().Name
		dnsRecord.Type = answer.Header().Rrtype
		if answer.Header().Rrtype == dns.TypeA {
			dnsRecord.CName = answer.(*dns.A).A.String()
		} else if answer.Header().Rrtype == dns.TypeAAAA {
			dnsRecord.CName = answer.(*dns.AAAA).AAAA.String()
		} else {
			dnsRecord.CName = answer.String()
		}
		frame.AddRecords([]DNSRecord{
			dnsRecord,
		})
	}
	frame.IsRequest = messageType == protocol.Request

	fb, ok := protocol.CreateFrameBase(streamBuffer, len(buf))
	if !ok {
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	frame.FrameBase = fb

	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&frame},
		ReadBytes:      int(len(buf)),
	}
}

func (k *DnsStreamParser) FindBoundary(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType, startPos int) int {
	return -1
}

func dnsRecordTypeName(r DNSRecord) string {
	dnsRecordTypeA := "A"
	dnsRecordTypeAAAA := "AAAA"
	dnsRecordTypeUnknown := "UNKNOWN"

	typeName := ""
	switch r.Type {
	case dns.TypeA:
		typeName = dnsRecordTypeA
	case dns.TypeAAAA:
		typeName = dnsRecordTypeAAAA
	default:
		typeName = dnsRecordTypeUnknown
	}
	return typeName
}

func (k *DnsStreamParser) processReqRespPair(reqFrame *Frame, respFrame *Frame) (*protocol.Record, error) {
	record := &protocol.Record{}
	record.Req = reqFrame
	record.Resp = respFrame
	return record, nil
}

// Match implements protocol.ProtocolStreamParser.
func (k *DnsStreamParser) Match(reqStreams map[protocol.StreamId]*protocol.ParsedMessageQueue, respStreams map[protocol.StreamId]*protocol.ParsedMessageQueue) []protocol.Record {
	records := make([]protocol.Record, 0)
	errorCnt := 0
	reqStream, ok1 := reqStreams[0]
	respStream, ok2 := respStreams[0]
	if !ok1 || !ok2 || len(*reqStream) == 0 || len(*respStream) == 0 {
		return records
	}
	for _, respStream := range *respStream {
		foundMatch := false
		for _, reqStream := range *reqStream {
			if reqStream.TimestampNs() > respStream.TimestampNs() {
				break
			}

			req := reqStream.(*Frame)
			resp := respStream.(*Frame)
			if req.Header.TXID == resp.Header.TXID {
				record, err := k.processReqRespPair(req, resp)
				if err != nil {
					errorCnt++
					common.ProtocolParserLog.Debugf("Failed to process DNS request/response pair: %v", err)
				} else {
					records = append(records, *record)
				}
				foundMatch = true
				req.Consumed = true
				break
			}
		}

		if !foundMatch {
			errorCnt++
		}

		// Clean-up consumed req_packets at the head.
		i := 0
		for ; i < len(*reqStream); i++ {
			if !(*reqStream)[i].(*Frame).Consumed {
				break
			}
		}

		if i > 0 {
			*reqStream = (*reqStream)[i:]
		}
	}

	*respStream = (*respStream)[0:0]
	return records
}
