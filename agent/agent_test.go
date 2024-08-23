package agent_test

import (
	"bufio"
	"container/list"
	"eapm-ebpf/agent"
	"eapm-ebpf/bpf"
	"eapm-ebpf/cmd"
	"eapm-ebpf/common"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"
)

type ConnEventAssertions struct {
	expectPid                  uint32
	expectLocalIp              string
	expectLocalAddrFamily      int
	expectLocalPort            int
	expectProtocol             bpf.AgentTrafficProtocolT
	expectRemoteIp             string
	expectRemoteFamily         int
	expectRemotePort           int
	expectReadBytes            uint64
	expectWriteBytes           uint64
	expectReadBytesPredicator  func(uint64) bool
	expectWriteBytesPredicator func(uint64) bool
	expectConnEventType        bpf.AgentConnTypeT
}

func AssertConnEvent(t *testing.T, connectEvent bpf.AgentConnEvtT, assert ConnEventAssertions) {
	t.Helper()
	if connectEvent.ConnInfo.ConnId.Upid.Pid != assert.expectPid {
		t.Fatalf("Pid Incorrect: %d != %d", connectEvent.ConnInfo.ConnId.Upid.Pid, assert.expectPid)
	}
	expectLocalIp := assert.expectLocalIp
	localIp := common.IntToIP(connectEvent.ConnInfo.Laddr.In4.SinAddr.S_addr)
	if expectLocalIp != "" && localIp != expectLocalIp {
		t.Fatalf("Local IP Incorrect: %s != %s", localIp, expectLocalIp)
	}
	localAddr := connectEvent.ConnInfo.Laddr
	localAddrFamily := localAddr.In4.SinFamily
	expectLocalAddrFamily := assert.expectLocalAddrFamily
	if expectLocalAddrFamily >= 0 && expectLocalAddrFamily != int(localAddrFamily) {
		t.Fatalf("LocalAddr Family Incorrect: %d != %d", localAddrFamily, expectLocalAddrFamily)
	}
	localPort := localAddr.In4.SinPort
	expectLocalPort := assert.expectLocalPort
	if expectLocalPort >= 0 && expectLocalPort != int(localPort) {
		t.Fatalf("Local Port Incorrect: %d != %d", localPort, expectLocalPort)
	}
	protocol := connectEvent.ConnInfo.Protocol
	expectProtocol := assert.expectProtocol
	if expectProtocol >= 0 && expectProtocol != protocol {
		t.Fatalf("Protocol Incorrect: %d != %d", protocol, expectProtocol)
	}
	remoteAddr := connectEvent.ConnInfo.Raddr
	remoteIp := common.IntToIP(remoteAddr.In4.SinAddr.S_addr)
	expectRemoteIp := assert.expectRemoteIp
	if expectRemoteIp != "" && expectRemoteIp != remoteIp {
		t.Fatalf("Remote IP Incorrect: %s != %s", remoteIp, expectRemoteIp)
	}
	remoteAddrFamily := remoteAddr.In4.SinFamily
	expectRemoteFamily := assert.expectRemoteFamily
	if expectRemoteFamily >= 0 && expectRemoteFamily != int(remoteAddrFamily) {
		t.Fatalf("RemoteAddr Family Incorrect: %d != %d", remoteAddrFamily, expectRemoteFamily)
	}
	remotePort := remoteAddr.In4.SinPort
	expectRemotePort := assert.expectRemotePort
	if expectRemotePort >= 0 && expectRemotePort != int(remotePort) {
		t.Fatalf("Remote Port Incorrect: %d != %d", remotePort, expectRemotePort)
	}
	if connectEvent.Ts <= 0 {
		t.Fatalf("Ts Incorrect: %d", connectEvent.Ts)
	}
	if connectEvent.ConnInfo.ConnId.Fd <= 0 {
		t.Fatalf("Fd Incorrect: %d", connectEvent.ConnInfo.ConnId.Fd)
	}
	readBytes := connectEvent.ConnInfo.ReadBytes
	expectReadBytes := assert.expectReadBytes
	if expectReadBytes >= 0 && readBytes != uint64(expectReadBytes) {
		t.Fatalf("ReadBytes Incorrect: %d != %d", readBytes, expectReadBytes)
	}
	if assert.expectReadBytesPredicator != nil && !assert.expectReadBytesPredicator(readBytes) {
		t.Fatalf("ReadBytes Predicate return false: %d", readBytes)
	}
	writeBytes := connectEvent.ConnInfo.WriteBytes
	expectWriteBytes := assert.expectWriteBytes
	if expectWriteBytes >= 0 && writeBytes != uint64(expectWriteBytes) {
		t.Fatalf("WriteBytes Incorrect: %d != %d", writeBytes, expectWriteBytes)
	}
	if assert.expectWriteBytesPredicator != nil && !assert.expectWriteBytesPredicator(writeBytes) {
		t.Fatalf("WriteBytes Predicate return false: %d", writeBytes)
	}
	expectConnEventType := assert.expectConnEventType
	if connectEvent.ConnType != expectConnEventType {
		t.Fatalf("ConnType Incorrect: %d", connectEvent.ConnType)
	}
}

type FindInterestedConnEventOptions struct {
	remotePort uint16
	localPort  uint16
	connType   bpf.AgentConnTypeT
	throw      bool
}

func findInterestedConnEvent(t *testing.T, connEventList []bpf.AgentConnEvtT, options FindInterestedConnEventOptions) bpf.AgentConnEvtT {
	for _, connEvent := range connEventList {
		if connEvent.ConnType == options.connType &&
			(connEvent.ConnInfo.Raddr.In4.SinPort == options.remotePort || options.remotePort == 0) &&
			(connEvent.ConnInfo.Laddr.In4.SinPort == options.localPort || options.localPort == 0) {
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

func TestConnectSyscall(t *testing.T) {
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
		})
		agent.SetInitCompletedHook(func() {
			wg.Done()
		})
		agent.SetCustomConnEventHook(func(evt *bpf.AgentConnEvtT) {
			connEventList = append(connEventList, *evt)
		})
		cmd.FilterPid = int64(pid)

		agent.SetupAgent()
	}(os.Getpid())

	wg.Wait()
	fmt.Println("Start Send Http Request")
	sendTestRequest(t, SendTestHttpRequestOptions{disableKeepAlived: true})

	time.Sleep(1 * time.Second)
	if len(connEventList) == 0 {
		t.Fatalf("no conn event!")
	}
	connectEvent := findInterestedConnEvent(t, connEventList, FindInterestedConnEventOptions{remotePort: 80, connType: bpf.AgentConnTypeTKConnect, throw: true})
	AssertConnEvent(t, connectEvent, ConnEventAssertions{
		expectPid:             uint32(os.Getpid()),
		expectRemotePort:      80,
		expectLocalAddrFamily: common.AF_INET,
		expectRemoteFamily:    common.AF_INET,
		expectReadBytes:       0,
		expectWriteBytes:      0,
		expectLocalPort:       -1,
		expectConnEventType:   bpf.AgentConnTypeTKConnect,
	})
}

func TestCloseSyscall(t *testing.T) {
	connEventList := make([]bpf.AgentConnEvtT, 0)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func(pid int) {
		agent.SetLoadBpfProgram(func(objs bpf.AgentObjects) *list.List {
			linkList := list.New()
			linkList.PushBack(bpf.AttachSyscallConnectEntry(objs))
			linkList.PushBack(bpf.AttachSyscallConnectExit(objs))
			linkList.PushBack(bpf.AttachSyscallCloseEntry(objs))
			linkList.PushBack(bpf.AttachSyscallCloseExit(objs))
			return linkList
		})
		agent.SetCustomSyscallEventHook(func(evt *bpf.SyscallEventData) {
		})
		agent.SetInitCompletedHook(func() {
			wg.Done()
		})
		agent.SetCustomConnEventHook(func(evt *bpf.AgentConnEvtT) {
			connEventList = append(connEventList, *evt)
		})
		cmd.FilterPid = int64(pid)

		agent.SetupAgent()
	}(os.Getpid())

	wg.Wait()
	fmt.Println("Start Send Http Request")
	sendTestRequest(t, SendTestHttpRequestOptions{disableKeepAlived: true})

	time.Sleep(1 * time.Second)
	if len(connEventList) == 0 {
		t.Fatalf("no conn event!")
	}
	connectEvent := findInterestedConnEvent(t, connEventList, FindInterestedConnEventOptions{remotePort: 80, connType: bpf.AgentConnTypeTKClose, throw: true})
	AssertConnEvent(t, connectEvent, ConnEventAssertions{
		expectPid:                  uint32(os.Getpid()),
		expectRemotePort:           80,
		expectLocalAddrFamily:      common.AF_INET,
		expectRemoteFamily:         common.AF_INET,
		expectReadBytesPredicator:  func(u uint64) bool { return u == 0 },
		expectWriteBytesPredicator: func(u uint64) bool { return u == 0 },
		expectLocalPort:            -1,
		expectConnEventType:        bpf.AgentConnTypeTKClose,
	})
}

func TestAccept(t *testing.T) {
	startCompleted := make(chan net.Listener)
	go StartEchoTcpServer(startCompleted)
	<-startCompleted
	fmt.Println("Start Echo Server Completed!")
	wg := sync.WaitGroup{}
	wg.Add(1)
	connEventList := make([]bpf.AgentConnEvtT, 0)
	go func(pid int) {
		agent.SetLoadBpfProgram(func(objs bpf.AgentObjects) *list.List {
			linkList := list.New()
			linkList.PushBack(bpf.AttachSyscallAcceptEntry(objs))
			linkList.PushBack(bpf.AttachSyscallAcceptExit(objs))
			return linkList
		})
		agent.SetCustomSyscallEventHook(func(evt *bpf.SyscallEventData) {
		})
		agent.SetInitCompletedHook(func() {
			wg.Done()
		})
		agent.SetCustomConnEventHook(func(evt *bpf.AgentConnEvtT) {
			connEventList = append(connEventList, *evt)
		})
		cmd.FilterPid = int64(pid)

		agent.SetupAgent()
	}(os.Getpid())

	wg.Wait()

	// ip, _ := common.GetIPAddrByInterfaceName("eth0")
	ip := "127.0.0.1"
	WriteToEchoTcpServer(ip+":"+fmt.Sprint(echoTcpServerPort), "hello\n", true)
	time.Sleep(1 * time.Second)
	if len(connEventList) == 0 {
		t.Fatalf("no conn event!")
	}

	connectEvent := findInterestedConnEvent(t, connEventList, FindInterestedConnEventOptions{localPort: uint16(echoTcpServerPort), connType: bpf.AgentConnTypeTKConnect, throw: true})
	AssertConnEvent(t, connectEvent, ConnEventAssertions{
		expectPid:                  uint32(os.Getpid()),
		expectRemotePort:           -1,
		expectLocalAddrFamily:      common.AF_INET,
		expectRemoteFamily:         common.AF_INET,
		expectReadBytesPredicator:  func(u uint64) bool { return u == 0 },
		expectWriteBytesPredicator: func(u uint64) bool { return u == 0 },
		expectLocalPort:            echoTcpServerPort,
		expectConnEventType:        bpf.AgentConnTypeTKConnect,
	})
}

func WriteToEchoTcpServer(server string, message string, readResponse bool) {

	connection, err := net.Dial("tcp", server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法连接到服务器 %s: %v\n", server, err)
		return
	}
	defer connection.Close()
	tcpConn := connection.(*net.TCPConn)
	tcpConnV := reflect.ValueOf(*tcpConn)
	fd := tcpConnV.FieldByName("conn").FieldByName("fd").Elem().FieldByName("pfd").FieldByName("Sysfd").Int()
	syscall.SetNonblock(int(fd), false)
	syscall.Write(int(fd), []byte(message))
	if readResponse {
		readBytes := make([]byte, 1000)
		syscall.Read(int(fd), readBytes)
		fmt.Printf("Read from conn: %s\n", string(readBytes))
	}
}

const echoTcpServerPort int = 10266

func StartEchoTcpServer(startCompleted chan net.Listener) {

	// obtain the port and prefix via program arguments
	port := ":" + fmt.Sprint(echoTcpServerPort)
	prefix := ""

	// create a tcp listener on the given port
	listener, err := net.Listen("tcp4", port)
	if err != nil {
		fmt.Println("failed to create listener, err:", err)
		os.Exit(1)
	}
	fmt.Printf("listening on %s, prefix: %s\n", listener.Addr(), prefix)
	startCompleted <- listener
	// listen for new connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("failed to accept connection, err:", err)
			continue
		}

		// pass an accepted connection to a handler goroutine
		go handleConnection(conn, prefix)
	}
}
func handleConnection(conn net.Conn, prefix string) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		// read client request data
		bytes, err := reader.ReadBytes(byte('\n'))
		if err != nil {
			if err != io.EOF {
				fmt.Println("failed to read data, err:", err)
			}
			return
		}
		fmt.Printf("request: %s", bytes)

		// prepend prefix and send as response
		line := fmt.Sprintf("%s %s", prefix, bytes)
		fmt.Printf("response: %s", line)
		conn.Write([]byte(line))
	}
}
