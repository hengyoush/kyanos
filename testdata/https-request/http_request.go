package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	// 检查参数是否足够
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <URL> <RequestCount>")
		return
	}

	// 获取 URL 和请求次数
	url := os.Args[1]
	requestCount, err := strconv.Atoi(os.Args[2])
	if err != nil || requestCount < 1 {
		fmt.Println("RequestCount must be a positive integer.")
		return
	}

	// 创建 HTTP 客户端，启用连接复用
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives:  false, // 启用 Keep-Alive 以保持连接
			DisableCompression: true,
		},
	}

	// 发起多次请求
	for i := 0; i < requestCount; i++ {
		// 发起 GET 请求
		response, err := client.Get(url)
		if err != nil {
			fmt.Printf("Request %d failed: %v\n", i+1, err)
			continue
		}

		// 读取并打印响应内容
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Printf("Failed to read response %d: %v\n", i+1, err)
			response.Body.Close()
			continue
		}
		fmt.Printf("Response %d:\n%s\n", i+1, string(body))
		response.Body.Close() // 关闭响应体以复用连接
		time.Sleep(1000 * time.Millisecond)
	}
}
