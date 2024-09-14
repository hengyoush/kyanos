package conn

import (
	"cmp"
	"kyanos/agent/protocol"
	"kyanos/common"
	"slices"
	"time"
)

type RecordsProcessor struct {
	records []RecordWithConn
}

type RecordWithConn struct {
	protocol.Record
	*Connection4
}

func (p *RecordsProcessor) Run(recordChannel <-chan RecordWithConn, ticker *time.Ticker) {
	for {
		select {
		case r := <-recordChannel:
			p.records = append(p.records, r)
		case <-ticker.C:
			if len(p.records) == 0 {
				continue
			}
			slices.SortFunc(p.records, func(r1, r2 RecordWithConn) int {
				return cmp.Compare(r1.Request().TimestampNs(), r2.Request().TimestampNs())
			})
			lastProcessIdx := -1
			now := time.Now().UnixMilli()
			for idx, record := range p.records {
				recordMills := common.NanoToMills(record.Response().TimestampNs())
				if float64(now)-recordMills >= 1000 {
					submitRecord(record.Record, record.Connection4)
					lastProcessIdx = idx
				}
			}
			if lastProcessIdx >= 0 {
				p.records = p.records[lastProcessIdx+1:]
			}
		}
	}
}

func submitRecord(record protocol.Record, c *Connection4) {
	var needSubmit bool

	needSubmit = c.MessageFilter.FilterByProtocol(c.Protocol)
	var duration uint64
	if c.IsServerSide() {
		duration = record.Request().TimestampNs() - record.Response().TimestampNs()
	} else {
		duration = record.Response().TimestampNs() - record.Request().TimestampNs()
	}

	needSubmit = needSubmit && c.LatencyFilter.Filter(float64(duration)/1000000)
	needSubmit = needSubmit &&
		c.SizeFilter.FilterByReqSize(int64(record.Request().ByteSize())) &&
		c.SizeFilter.FilterByRespSize(int64(record.Response().ByteSize()))
	if parser := c.GetProtocolParser(c.Protocol); needSubmit && parser != nil {
		var parsedRequest, parsedResponse protocol.ParsedMessage
		if c.MessageFilter.FilterByRequest() {
			parsedRequest = record.Request()
		}
		if c.MessageFilter.FilterByResponse() {
			parsedResponse = record.Response()
		}
		if parsedRequest != nil || parsedResponse != nil {
			needSubmit = c.MessageFilter.Filter(parsedRequest, parsedResponse)
		} else {
			needSubmit = true
		}

	} else {
		needSubmit = false
	}
	if needSubmit {
		RecordFunc(record, c)
	}
}
