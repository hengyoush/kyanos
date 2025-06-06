package protocol

import (
	"bufio"
	"fmt"
	"io"
	"kyanos/agent/buffer"
	"kyanos/bpf"
	"kyanos/common"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"k8s.io/utils/ptr"
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

func (h *HTTPStreamParser) Match(reqStreams map[StreamId]*ParsedMessageQueue, respStreams map[StreamId]*ParsedMessageQueue) []Record {
	reqStream, ok1 := reqStreams[0]
	respStream, ok2 := respStreams[0]
	if !ok1 || !ok2 {
		return []Record{}
	}
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

func (h *HTTPStreamParser) ParseResponse(buf string, messageType MessageType, timestamp uint64, seq uint64, streamBuffer *buffer.StreamBuffer) ParseResult {
	reader := strings.NewReader(buf)
	bufioReader := bufio.NewReader(reader)
	resp, err := http.ReadResponse(bufioReader, nil)
	parseResult := ParseResult{}
	if err != nil {
		return h.handleReadResponseError(err, buf, streamBuffer, messageType, timestamp, seq)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return h.handleReadBodyError(err, buf, streamBuffer, messageType, timestamp, seq)
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

func (h *HTTPStreamParser) handleReadResponseError(err error, buf string, streamBuffer *buffer.StreamBuffer, messageType MessageType, timestamp uint64, seq uint64) ParseResult {
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

func (h *HTTPStreamParser) handleReadBodyError(err error, buf string, streamBuffer *buffer.StreamBuffer, messageType MessageType, timestamp uint64, seq uint64) ParseResult {
	parseResult := ParseResult{}
	boundary := h.FindBoundary(streamBuffer, messageType, 0)
	if boundary > 0 {
		parseResult.ReadBytes = boundary
		parseResult.ParsedMessages = []ParsedMessage{
			&ParsedHttpResponse{
				FrameBase: NewFrameBase(timestamp, boundary, seq),
				buf:       []byte(buf[:boundary]),
			},
		}
		parseResult.ParseState = Success
		return parseResult
	} else if fakeDataIdx, _ := fakeDataMarkIndex([]byte(buf)); fakeDataIdx != -1 {
		fakeDataSize := getFakeDataSize([]byte(buf), fakeDataIdx)
		if len(buf) >= fakeDataIdx+int(fakeDataSize)+fakeDataMarkLen {
			parseResult.ReadBytes = fakeDataIdx + int(fakeDataSize) + fakeDataMarkLen
			parseResult.ParsedMessages = []ParsedMessage{
				&ParsedHttpResponse{
					FrameBase: NewFrameBase(timestamp, parseResult.ReadBytes, seq),
					buf:       []byte(buf[:parseResult.ReadBytes]),
				},
			}
			parseResult.ParseState = Success
			return parseResult
		}
	}
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

func (h *HTTPStreamParser) ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult {
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
		return h.ParseResponse(buf, messageType, ts, head.LeftBoundary(), streamBuffer)
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

func (req *ParsedHttpRequest) StreamId() StreamId {
	return 0
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

func (req *ParsedHttpResponse) StreamId() StreamId {
	return 0
}

var _ ProtocolFilter = HttpFilter{}

type HttpFilter struct {
	TargetPath       string
	TargetPathReg    *regexp.Regexp
	TargetPathPrefix string
	TargetHostName   string
	TargetMethods    []string
	needFilter       *bool
}

func (filter HttpFilter) FilterByProtocol(protocol bpf.AgentTrafficProtocolT) bool {
	return protocol == bpf.AgentTrafficProtocolTKProtocolHTTP
}

func (filter HttpFilter) FilterByRequest() bool {
	if filter.needFilter != nil {
		return *filter.needFilter
	}
	filter.needFilter = ptr.To(len(filter.TargetPath) > 0 ||
		filter.TargetPathReg != nil ||
		len(filter.TargetPathPrefix) > 0 ||
		len(filter.TargetMethods) > 0 ||
		len(filter.TargetHostName) > 0)
	return *filter.needFilter
}

func (filter HttpFilter) FilterByResponse() bool {
	return false
}

// Filter filters HTTP requests based on various criteria such as path, path prefix, path regex, method, and host name.
// It returns true if the request matches all the specified criteria, otherwise it returns false.
//
// The filtering logic is as follows:
// - If TargetPath is specified, the request path must exactly match TargetPath.
// - If TargetPathPrefix is specified, the request path must start with TargetPathPrefix.
// - If TargetPathReg is specified, the request path must match the regular expression TargetPathReg.
// - If TargetMethods is specified, the request method must be one of the methods in TargetMethods.
// - If TargetHostName is specified, the request host must exactly match TargetHostName.
func (filter HttpFilter) Filter(parsedReq ParsedMessage, _ ParsedMessage) bool {
	req, ok := parsedReq.(*ParsedHttpRequest)
	if !ok {
		common.ProtocolParserLog.Warnf("[HttpFilter] cast to http.Request failed: %v\n", req)
		return false
	}
	common.ProtocolParserLog.Debugf("[HttpFilter] filtering request: %v\n", req)

	if len(filter.TargetPath) > 0 && filter.TargetPath != req.Path {
		return false
	}

	if len(filter.TargetPathPrefix) > 0 && !strings.HasPrefix(req.Path, filter.TargetPathPrefix) {
		return false
	}

	if filter.TargetPathReg != nil && !filter.TargetPathReg.MatchString(req.Path) {
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

func (HttpFilter) Protocol() bpf.AgentTrafficProtocolT {
	return bpf.AgentTrafficProtocolTKProtocolHTTP
}
