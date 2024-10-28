package protocol

import (
	"bufio"
	"fmt"
	"io"
	"kyanos/agent/buffer"
	"kyanos/bpf"
	"kyanos/common"
	"net/http"
	"slices"
	"strings"
)

var _ ProtocolStreamParser = &HTTPStreamParser{}

func init() {
	ParsersMap[bpf.AgentTrafficProtocolTKProtocolHTTP] = func() ProtocolStreamParser {
		return &HTTPStreamParser{}
	}
}

var HTTP_REQ_START_PATTERN = []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "}
var HTTP_RESP_START_PATTERN = []string{"HTTP/1.1 ", "HTTP/1.0 "}
var HTTP_BOUNDARY_MARKER = "\r\n\r\n"

type HTTPStreamParser struct {
}

func (h *HTTPStreamParser) Match(reqStream *[]ParsedMessage, respStream *[]ParsedMessage) []Record {
	return matchByTimestamp(reqStream, respStream)
}

func (h *HTTPStreamParser) FindBoundary(streamBuffer *buffer.StreamBuffer, messageType MessageType, startPos int) int {
	var matchPattern []string
	switch messageType {
	case Request:
		matchPattern = HTTP_REQ_START_PATTERN
	case Response:
		matchPattern = HTTP_RESP_START_PATTERN
	}

	buf := string(streamBuffer.Head().Buffer())
	for startPos < len(buf) {
		boundaryIndex := strings.Index(buf[startPos:], HTTP_BOUNDARY_MARKER)
		if boundaryIndex == -1 {
			return -1
		}
		boundaryIndex += startPos
		substr := buf[startPos:boundaryIndex]
		prevPos := -1
		for _, pattern := range matchPattern {
			patternIndex := strings.Index(substr, pattern)
			if patternIndex != -1 {
				if prevPos == -1 {
					prevPos = patternIndex
				} else {
					prevPos = max(prevPos, patternIndex)
				}
			}
		}

		if prevPos != -1 {
			return startPos + prevPos
		}

		startPos = boundaryIndex + len(HTTP_BOUNDARY_MARKER)
	}

	return -1
}

func (h *HTTPStreamParser) ParseRequest(buf string, messageType MessageType, timestamp uint64, seq uint64) ParseResult {
	reader := strings.NewReader(buf)
	bufioReader := bufio.NewReader(reader)
	req, err := http.ReadRequest(bufioReader)
	parseResult := ParseResult{}
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return ParseResult{
				ParseState: NeedsMoreData,
			}
		} else {
			return ParseResult{
				ParseState: Invalid,
			}
		}
	} else {
		if req.ContentLength > 0 {
			reqBody, err := io.ReadAll(req.Body)
			if err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					return ParseResult{
						ParseState: NeedsMoreData,
					}
				} else {
					return ParseResult{
						ParseState: Invalid,
					}
				}
			}
			if len(reqBody) != int(req.ContentLength) {
				fmt.Print("!")
			}
		}
		readIndex := common.GetBufioReaderReadIndex(bufioReader)
		parseResult.ReadBytes = readIndex
		parseResult.ParsedMessages = []ParsedMessage{
			&ParsedHttpRequest{
				FrameBase: NewFrameBase(timestamp, readIndex, seq),
				Host:      req.Host,
				Method:    req.Method,
				Path:      req.URL.Path,
				buf:       []byte(buf[:readIndex]),
			},
		}
		parseResult.ParseState = Success
		return parseResult
	}
}

func (h HTTPStreamParser) ParseResponse(buf string, messageType MessageType, timestamp uint64, seq uint64) ParseResult {
	reader := strings.NewReader(buf)
	bufioReader := bufio.NewReader(reader)
	resp, err := http.ReadResponse(bufioReader, nil)
	parseResult := ParseResult{}
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return ParseResult{
				ParseState: NeedsMoreData,
			}
		} else {
			return ParseResult{
				ParseState: Invalid,
			}
		}
	} else {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return ParseResult{
					ParseState: NeedsMoreData,
				}
			} else {
				return ParseResult{
					ParseState: Invalid,
				}
			}
		}
		readIndex := common.GetBufioReaderReadIndex(bufioReader)
		if readIndex == 0 && len(respBody) > 0 {
			readIndex = len(buf)
		} else if readIndex == 0 {
			return ParseResult{
				ParseState: NeedsMoreData,
			}
		}
		parseResult.ReadBytes = readIndex
		parseResult.ParsedMessages = []ParsedMessage{
			&ParsedHttpResponse{
				FrameBase: NewFrameBase(timestamp, readIndex, seq),
				buf:       []byte(buf[:readIndex]),
			},
		}
		parseResult.ParseState = Success
		return parseResult
	}
}

func (h HTTPStreamParser) ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult {
	head := streamBuffer.Head()
	buf := string(head.Buffer())
	ts, ok := streamBuffer.FindTimestampBySeq(head.LeftBoundary())
	if !ok {
		return ParseResult{
			ParseState: Invalid,
		}
	}
	switch messageType {
	case Request:
		return h.ParseRequest(buf, messageType, ts, head.LeftBoundary())
	case Response:
		return h.ParseResponse(buf, messageType, ts, head.LeftBoundary())
	default:
		panic("messageType invalid")
	}
}

type ParsedHttpRequest struct {
	FrameBase
	Path   string
	Host   string
	Method string

	buf []byte
}

var _ ParsedMessage = &ParsedHttpRequest{}
var _ ParsedMessage = &ParsedHttpResponse{}
var _ StatusfulMessage = &ParsedHttpResponse{}

func (req *ParsedHttpRequest) FormatToSummaryString() string {
	return fmt.Sprintf("[HTTP] %s http://%s%s", req.Method, req.Host, req.Path)
}

func (req *ParsedHttpRequest) FormatToString() string {
	return string(req.buf)
}

func (req *ParsedHttpRequest) IsReq() bool {
	return true
}

type ParsedHttpResponse struct {
	FrameBase
	buf []byte
}

func (resp *ParsedHttpResponse) FormatToSummaryString() string {
	return fmt.Sprintf("[HTTP] Response len: %d", resp.byteSize)
}
func (resp *ParsedHttpResponse) Status() ResponseStatus {
	return SuccessStatus
}

func (resp *ParsedHttpResponse) FormatToString() string {
	return string(resp.buf)
}
func (resp *ParsedHttpResponse) IsReq() bool {
	return false
}

var _ ProtocolFilter = HttpFilter{}

type HttpFilter struct {
	TargetPath     string
	TargetHostName string
	TargetMethods  []string
}

func (filter HttpFilter) FilterByProtocol(protocol bpf.AgentTrafficProtocolT) bool {
	return protocol == bpf.AgentTrafficProtocolTKProtocolHTTP
}

func (filter HttpFilter) FilterByRequest() bool {
	return filter.TargetPath != "" || len(filter.TargetMethods) > 0 || filter.TargetHostName != ""
}

func (filter HttpFilter) FilterByResponse() bool {
	return false
}

func (filter HttpFilter) Filter(parsedReq ParsedMessage, parsedResp ParsedMessage) bool {
	req, ok := parsedReq.(*ParsedHttpRequest)
	if !ok {
		common.ProtocolParserLog.Warnf("[HttpFilter] cast to http.Request failed: %v\n", req)
		return false
	}

	if filter.TargetPath != "" && filter.TargetPath != req.Path {
		return false
	}
	if len(filter.TargetMethods) > 0 && !slices.Contains(filter.TargetMethods, req.Method) {
		return false
	}
	if filter.TargetHostName != "" && filter.TargetHostName != req.Host {
		return false
	}
	return true
}
