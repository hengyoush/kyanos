package agent_test

import (
	"container/list"
	"eapm-ebpf/agent"
	"eapm-ebpf/bpf"
	"eapm-ebpf/cmd"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

type FindInterestedConnEventOptions struct {
	remotePort uint16
	connType   bpf.AgentConnTypeT
	throw      bool
}

func findInterestedConnEvent(t *testing.T, connEventList []bpf.AgentConnEvtT, options FindInterestedConnEventOptions) bpf.AgentConnEvtT {
	for _, connEvent := range connEventList {
		if connEvent.ConnType == options.connType && connEvent.ConnInfo.Raddr.In4.SinPort == options.remotePort {
			return connEvent
		}
	}
	if options.throw {
		t.Fatalf("no conn event found for: %v", options)
	}
	return bpf.AgentConnEvtT{}
}

type SendTestHttpRequestOptions struct {
	disableKeepAlived bool
}

func sendTestRequest(t *testing.T, options SendTestHttpRequestOptions) error {
	// 创建http客户端，连接baidu.com
	// 创建一个HTTP客户端（实际上，在这个例子中直接使用http.Get也是可以的，因为它内部会创建一个默认的客户端）
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: options.disableKeepAlived,
		},
	}

	// 创建一个请求
	req, err := http.NewRequest("GET", "http://www.baidu.com", nil)
	resp, err := client.Do(req)
	if err != nil {
		// 如果有错误，则打印错误并退出
		t.Fatal("Error sending request:", err)
		return err
	}
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		// 如果有错误，则打印错误并退出
		t.Fatal("Error reading response body:", err)
		return err
	}
	fmt.Printf("Status Code: %d\n", resp.StatusCode)
	resp.Body.Close()
	return err
}

func TestSend(t *testing.T) {
	sendTestRequest(t, SendTestHttpRequestOptions{disableKeepAlived: true})
}

func TestAgent(t *testing.T) {
	pid := os.Getpid()
	connEventList := make([]bpf.AgentConnEvtT, 0)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func(pid int) {
		agent.SetLoadBpfProgram(func(objs bpf.AgentObjects) *list.List {
			linkList := list.New()
			linkList.PushBack(bpf.AttachSyscallConnectEntry(objs))
			linkList.PushBack(bpf.AttachSyscallConnectExit(objs))
			return linkList
		})
		agent.SetCustomSyscallEventHook(func(evt *bpf.SyscallEventData) {
			fmt.Println("syscall event arrived!")
		})
		agent.SetInitCompletedHook(func() {
			fmt.Println("Init Completed!")
			wg.Done()
		})
		agent.SetCustomConnEventHook(func(evt *bpf.AgentConnEvtT) {
			fmt.Println("conn event arrived!")
			connEventList = append(connEventList, *evt)
		})
		cmd.FilterPid = int64(pid)

		agent.SetupAgent()
	}(pid)

	wg.Wait()
	fmt.Println("Start Send Http Request")
	sendTestRequest(t, SendTestHttpRequestOptions{disableKeepAlived: true})

	time.Sleep(1 * time.Second)
	if len(connEventList) == 0 {
		t.Fatalf("no conn event!")
	}
	connectEvent := findInterestedConnEvent(t, connEventList, FindInterestedConnEventOptions{remotePort: 80, connType: bpf.AgentConnTypeTKConnect, throw: true})
	if connectEvent.ConnType != bpf.AgentConnTypeTKConnect {
		t.Fatalf("ConnType Incorrect: %d", connectEvent.ConnType)
	}
	if connectEvent.ConnInfo.ConnId.Upid.Pid != uint32(pid) {
		t.Fatalf("Pid Incorrect: %d != %d", connectEvent.ConnInfo.ConnId.Upid.Pid, uint32(pid))
	}
	if connectEvent.ConnInfo.Raddr.In4.SinPort != 80 {
		t.Fatalf("Remote Port Incorrect: %d != %d", connectEvent.ConnInfo.Raddr.In4.SinPort, 80)
	}

	// closeEvent := findInterestedConnEvent(t, connEventList, FindInterestedConnEventOptions{remotePort: 80, connType: bpf.AgentConnTypeTKClose, throw: true})
	// if closeEvent.ConnType != bpf.AgentConnTypeTKClose {
	// 	t.Fatalf("ConnType Incorrect: %d", closeEvent.ConnType)
	// }
	// if closeEvent.ConnInfo.ConnId.Upid.Pid != uint32(pid) {
	// 	t.Fatalf("Pid Incorrect: %d != %d", closeEvent.ConnInfo.ConnId.Upid.Pid, uint32(pid))
	// }
	// if closeEvent.ConnInfo.Raddr.In4.SinPort != 80 {
	// 	t.Fatalf("Remote Port Incorrect: %d != %d", closeEvent.ConnInfo.Raddr.In4.SinPort, 80)
	// }
}
