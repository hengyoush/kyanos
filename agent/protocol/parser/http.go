package parser

import (
	"bufio"
	"bytes"
	"errors"
	"kyanos/agent/protocol"
	"net/http"
)

var _ protocol.ProtocolParser = HttpParser{}

type HttpParser struct {
}

type ParsedHttpRequest struct {
	protocol.FrameBase
	Path   string
	Host   string
	Method string

	buf []byte
}

func (req *ParsedHttpRequest) FormatToString() string {
	return string(req.buf)
}

type ParsedHttpResponse struct {
	protocol.FrameBase
	buf []byte
}

func (resp *ParsedHttpResponse) FormatToString() string {
	return string(resp.buf)
}

func (HttpParser) Parse(msg *protocol.BaseProtocolMessage) (protocol.ParsedMessage, error) {
	if msg.IsTruncated() {
		return nil, errors.New("Can't parse truncated data")
	}
	reader := bytes.NewReader(msg.Data())
	if msg.IsReq {
		req, err := http.ReadRequest(bufio.NewReader(reader))
		if err != nil {
			return nil, err
		}
		return &ParsedHttpRequest{
			FrameBase: protocol.NewFrameBase(msg.StartTs, int(msg.TotalBytes())),
			Path:      req.URL.Path,
			Host:      req.Host,
			Method:    req.Method,
			buf:       msg.Data(),
		}, nil
	} else {
		_, err := http.ReadResponse(bufio.NewReader(reader), nil)
		if err != nil {
			return nil, err
		}
		return &ParsedHttpResponse{
			FrameBase: protocol.NewFrameBase(msg.StartTs, int(msg.TotalBytes())),
			buf:       msg.Data(),
		}, nil
	}
}
