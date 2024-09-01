package protocol_test

import (
	"bufio"
	"fmt"
	"io"
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	"kyanos/common"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const httpRespMessage = "HTTP/1.1 200 OK\r\n" +
	"Content-Type: bar\r\n" +
	"Content-Length: 21\r\n" +
	"\r\n" +
	"pixielabs is awesome!"

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

func TestReadContentLength(t *testing.T) {
	message := "POST /ca_report.cgi HTTP/1.1\r\nAccept-Encoding: identity\r\nContent-Length: 383\r\nHost: 169.254.0.4\r\nContent-Type: application/json\r\nConnection: close\r\nUser-Agent: Python-urllib/2.6\r\n\r\n"

	reader := strings.NewReader(message)
	x := bufio.NewReader(reader)

	req, _ := http.ReadRequest(x)

	_, err := io.ReadAll(req.Body)
	fmt.Println(err)
}

func TestYyy(t *testing.T) {
	reader := strings.NewReader(httpRespMessage)
	x := bufio.NewReader(reader)
	resp, _ := http.ReadResponse(x, nil)
	io.ReadAll(resp.Body)
	index := common.GetBufioReaderReadIndex(x)
	fmt.Println(index)
}

func TestFoundBoundaryForHttpRequest(t *testing.T) {
	buffer := buffer.New(1000)
	httpMessage := "GET /abc HTTP/1.1\r\nHost: www.baidu.com\r\n\r\nGET /abc2 HTTP/1.1\r\nHost: www.baidu.com\r\n\r\n"
	buffer.Add(10, []byte(httpMessage), 10000)

	parser := protocol.HTTPStreamParser{}
	bound := parser.FindBoundary(buffer, protocol.Request, 0)
	assert.Equal(t, 0, bound)
}

func TestFoundBoundaryForHttpRequest_FirstMessageIsTruncated(t *testing.T) {
	buffer := buffer.New(1000)
	httpMessage := "ET /abc HTTP/1.1\r\nHost: www.baidu.com\r\n\r\nGET /abc2 HTTP/1.1\r\nHost: www.baidu.com\r\n\r\n"
	buffer.Add(10, []byte(httpMessage), 10000)

	parser := protocol.HTTPStreamParser{}
	bound := parser.FindBoundary(buffer, protocol.Request, 0)
	assert.Equal(t, strings.Index(httpMessage, "GET"), bound)
}

func TestFoundBoundaryForHttpRequestNotFound(t *testing.T) {
	buffer := buffer.New(1000)
	httpMessage := "ET /abc HTTP/1.1\r\nHost: www.baidu.com\r\n\r"
	buffer.Add(10, []byte(httpMessage), 10000)

	parser := protocol.HTTPStreamParser{}
	bound := parser.FindBoundary(buffer, protocol.Request, 0)
	assert.Equal(t, -1, bound)
}

func TestFoundBoundaryForHttpResponse(t *testing.T) {
	buffer := buffer.New(1000)
	httpMessage :=
		"HTTP/1.1 200 OK\r\n" +
			"Content-Type: bar\r\n" +
			"Content-Length: 21\r\n" +
			"\r\n" +
			"pixielabs is awesome!"
	buffer.Add(10, []byte(httpMessage), 10000)

	parser := protocol.HTTPStreamParser{}
	bound := parser.FindBoundary(buffer, protocol.Response, 0)
	assert.Equal(t, 0, bound)
}

func TestFoundBoundaryForHttpResponse_FirstIsTruncated(t *testing.T) {
	buffer := buffer.New(1000)
	httpMessage := httpRespMessage
	httpMessage += httpMessage
	httpMessage = httpMessage[1:]
	buffer.Add(10, []byte(httpMessage), 10000)

	parser := protocol.HTTPStreamParser{}
	bound := parser.FindBoundary(buffer, protocol.Response, 0)
	assert.Equal(t, strings.Index(httpMessage, "HTTP/1.1"), bound)
}

func TestFoundBoundaryForHttpResponseNotFound(t *testing.T) {
	buffer := buffer.New(1000)
	buffer.Add(10, []byte(httpRespMessage[1:]), 10000)

	parser := protocol.HTTPStreamParser{}
	bound := parser.FindBoundary(buffer, protocol.Response, 0)
	assert.Equal(t, -1, bound)
}

func TestParseRequest(t *testing.T) {
	buffer := buffer.New(1000)
	httpMessage := "GET /abc HTTP/1.1\r\nHost: www.baidu.com\r\n\r\n"
	httpMessage += httpMessage
	buffer.Add(10, []byte(httpMessage), 10000)

	parser := protocol.HTTPStreamParser{}

	parseResult := parser.ParseRequest(httpMessage, protocol.Request, 10, 20)

	assert.Equal(t, protocol.Success, parseResult.ParseState)
	assert.Equal(t, 1, len(parseResult.ParsedMessages))
	message := parseResult.ParsedMessages[0]
	assert.Equal(t, len(httpMessage)/2, message.ByteSize())
	assert.Equal(t, true, message.IsReq())
	assert.Equal(t, uint64(10), message.TimestampNs())
	assert.Equal(t, uint64(20), message.Seq())
	httpReq, ok := message.(*protocol.ParsedHttpRequest)
	assert.True(t, ok)
	assert.Equal(t, "GET", httpReq.Method)
	assert.Equal(t, "/abc", httpReq.Path)
	assert.Equal(t, "www.baidu.com", httpReq.Host)
}

func TestParseResponse(t *testing.T) {
	buffer := buffer.New(1000)
	httpMessage := httpRespMessage
	httpMessage += httpMessage
	buffer.Add(10, []byte(httpMessage), 10000)

	parser := protocol.HTTPStreamParser{}

	parseResult := parser.ParseResponse(httpMessage, protocol.Response, 10, 20)

	assert.Equal(t, protocol.Success, parseResult.ParseState)
	assert.Equal(t, 1, len(parseResult.ParsedMessages))
	message := parseResult.ParsedMessages[0]
	assert.Equal(t, len(httpMessage)/2, message.ByteSize())
	assert.Equal(t, false, message.IsReq())
	assert.Equal(t, uint64(10), message.TimestampNs())
	assert.Equal(t, uint64(20), message.Seq())
}
