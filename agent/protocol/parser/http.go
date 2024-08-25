package parser

import (
	"bufio"
	"bytes"
	"eapm-ebpf/agent/protocol"
	"errors"
	"net/http"
)

var _ ProtocolParser = HttpParser{}

type HttpParser struct {
}

func (HttpParser) Parse(msg *protocol.BaseProtocolMessage) (any, error) {
	if msg.IsTruncated() {
		return nil, errors.New("Can't parse truncated data")
	}
	reader := bytes.NewReader(msg.Data())
	if msg.IsReq {
		req, err := http.ReadRequest(bufio.NewReader(reader))
		if err != nil {
			return nil, err
		}
		return req, nil
	} else {
		resp, err := http.ReadResponse(bufio.NewReader(reader), nil)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
}
