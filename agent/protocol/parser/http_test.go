package parser_test

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func TestXxx(t *testing.T) {
	reader := bytes.NewReader([]byte("GET /?key=value&key=value HTTP/1.1\n" +
		"Accept-Language: zh-CN,zh;q=0.9\n" +
		"Host:www.baidu.com"))
	req, err := http.ReadRequest(bufio.NewReader(reader))
	if err != nil {
		fmt.Printf("err: %v\n", err)
	} else {
		fmt.Printf("req: %v\n", req)
	}
}

func TestUriParse(t *testing.T) {
	uri, _ := url.Parse("http://123.1.1.1/abc/api")
	fmt.Println(uri.RawPath)
	fmt.Println(uri.Path)
}
