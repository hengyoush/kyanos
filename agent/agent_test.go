package agent_test

import (
	"bufio"
	"container/list"
	"eapm-ebpf/agent"
	"eapm-ebpf/agent/conn"
	"eapm-ebpf/bpf"
	"eapm-ebpf/cmd"
	"eapm-ebpf/common"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
		t.Fatalf("Pid Incorrect: %d !=  %d", connectEvent.ConnInfo.ConnId.Upid.Pid, assert.expectPid)
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

type SyscallDataEventAssertConditions struct {
	ignoreConnIdDirect    bool
	connIdDirect          bpf.AgentTrafficDirectionT
	ignorePid             bool
	pid                   uint64
	ignoreFd              bool
	fd                    uint32
	ignoreFuncName        bool
	funcName              string
	ignoreDataLen         bool
	dataLen               uint32
	ignoreSeq             bool
	seq                   uint64
	ignoreStep            bool
	step                  bpf.AgentStepT
	tsAssertFunction      func(uint64) bool
	bufSizeAssertFunction func(uint32) bool
	bufAssertFunction     func([]byte) bool
}

func AssertSyscallEventData(t *testing.T, event bpf.SyscallEventData, conditions SyscallDataEventAssertConditions) {
	connId := event.SyscallEvent.Ke.ConnIdS
	direct := connId.Direct
	if !conditions.ignoreConnIdDirect {
		assert.Equal(t, conditions.connIdDirect, direct)
	}
	pid := connId.TgidFd >> 32
	if !conditions.ignorePid {
		assert.Equal(t, conditions.pid, pid)
	}
	fd := uint32(connId.TgidFd)
	if !conditions.ignoreFd {
		assert.Equal(t, conditions.fd, fd)
	}
	funcName := event.SyscallEvent.Ke.FuncName
	if !conditions.ignoreFuncName {
		assert.Equal(t, conditions.funcName, common.Int8ToStr(funcName[:len(conditions.funcName)]))
	}
	dataLen := event.SyscallEvent.Ke.Len
	if !conditions.ignoreDataLen {
		assert.Equal(t, conditions.dataLen, dataLen)
	}
	seq := event.SyscallEvent.Ke.Seq
	if !conditions.ignoreSeq {
		assert.Equal(t, conditions.seq, seq)
	}
	step := event.SyscallEvent.Ke.Step
	if !conditions.ignoreStep {
		assert.Equal(t, conditions.step, step)
	}
	ts := event.SyscallEvent.Ke.Ts
	if conditions.tsAssertFunction != nil {
		assert.True(t, conditions.tsAssertFunction(ts))
	}
	bufSize := event.SyscallEvent.BufSize
	if conditions.bufSizeAssertFunction != nil {
		assert.True(t, conditions.bufSizeAssertFunction(bufSize))
	}
	buf := event.Buf
	if conditions.bufAssertFunction != nil {
		assert.True(t, conditions.bufAssertFunction(buf))
	}
}

type FindInterestedConnEventOptions struct {
	findByRemotePort bool
	remotePort       uint16
	findByLocalPort  bool
	localPort        uint16
	findByConnType   bool
	connType         bpf.AgentConnTypeT
	findByTgidFd     bool
	tgidFd           uint64
	throw            bool
}

type FindInterestedSyscallEventOptions struct {
	findByRemotePort bool
	remotePort       uint16
	findByLocalPort  bool
	localPort        uint16
	throw            bool

	connEventList []bpf.AgentConnEvtT
}

var CONN_EVENT_NOT_FOUND bpf.AgentConnEvtT = bpf.AgentConnEvtT{}

func findInterestedConnEvent(t *testing.T, connEventList []bpf.AgentConnEvtT, options FindInterestedConnEventOptions) []bpf.AgentConnEvtT {
	t.Helper()
	resultList := make([]bpf.AgentConnEvtT, 0)
	for _, connEvent := range connEventList {
		if options.findByRemotePort && options.remotePort != connEvent.ConnInfo.Raddr.In4.SinPort {
			continue
		}
		if options.findByLocalPort && options.localPort != connEvent.ConnInfo.Laddr.In4.SinPort {
			continue
		}
		if options.findByConnType && options.connType != connEvent.ConnType {
			continue
		}
		if options.findByTgidFd && options.tgidFd != (uint64(connEvent.ConnInfo.ConnId.Upid.Pid)<<32|uint64(connEvent.ConnInfo.ConnId.Fd)) {
			continue
		}
		resultList = append(resultList, connEvent)
	}
	if options.throw && len(resultList) == 0 {
		t.Fatalf("no conn event found for: %v", options)
	}
	return resultList
}

func findInterestedSyscallEvents(t *testing.T, syscallEventList []bpf.SyscallEventData, options FindInterestedSyscallEventOptions) []bpf.SyscallEventData {
	t.Helper()
	resultList := make([]bpf.SyscallEventData, 0)
	for _, each := range syscallEventList {
		connectEvents := findInterestedConnEvent(t, options.connEventList, FindInterestedConnEventOptions{
			findByTgidFd:   true,
			findByConnType: true,
			tgidFd:         each.SyscallEvent.Ke.ConnIdS.TgidFd,
			connType:       bpf.AgentConnTypeTKConnect,
			throw:          false,
		})
		if len(connectEvents) == 0 {
			continue
		}
		connectEvent := connectEvents[0]
		if options.findByRemotePort && connectEvent.ConnInfo.Raddr.In4.SinPort != options.remotePort {
			continue
		}
		if options.findByLocalPort && connectEvent.ConnInfo.Laddr.In4.SinPort != options.localPort {
			continue
		}
		resultList = append(resultList, each)
	}
	if options.throw && len(resultList) == 0 {
		t.Fatalf("no syscall event found for: %v", options)
	}
	return resultList
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

func TestConnectSyscall(t *testing.T) {
	connEventList := make([]bpf.AgentConnEvtT, 0)
	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
		},
		&connEventList,
		nil,
		nil)
	fmt.Println("Start Send Http Request")
	sendTestRequest(t, SendTestHttpRequestOptions{disableKeepAlived: true})

	time.Sleep(1 * time.Second)
	if len(connEventList) == 0 {
		t.Fatalf("no conn event!")
	}
	connectEvent := findInterestedConnEvent(t, connEventList, FindInterestedConnEventOptions{
		findByRemotePort: true,
		findByConnType:   true,
		remotePort:       80,
		connType:         bpf.AgentConnTypeTKConnect,
		throw:            true})[0]
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

func StartAgent(bpfAttachFunctions []bpf.AttachBpfProgFunction, connEventList *[]bpf.AgentConnEvtT,
	syscallEventList *[]bpf.SyscallEventData, connManagerInitHook func(*conn.ConnManager)) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func(pid int) {
		agent.SetLoadBpfProgram(func(objs bpf.AgentObjects) *list.List {
			progs := list.New()
			for _, each := range bpfAttachFunctions {
				progs.PushBack(each(objs))
			}
			return progs
		})
		agent.SetCustomSyscallEventHook(func(evt *bpf.SyscallEventData) {
			if syscallEventList != nil {
				*syscallEventList = append(*syscallEventList, *evt)
			}
		})
		agent.SetInitCompletedHook(func() {
			wg.Done()
		})
		agent.SetCustomConnEventHook(func(evt *bpf.AgentConnEvtT) {
			if connEventList != nil {
				*connEventList = append(*connEventList, *evt)
			}
		})
		if connManagerInitHook != nil {
			agent.SetConnManagerInitHook(connManagerInitHook)
		}
		cmd.FilterPid = int64(pid)

		agent.SetupAgent()
	}(os.Getpid())

	wg.Wait()
}

func TestCloseSyscall(t *testing.T) {
	connEventList := make([]bpf.AgentConnEvtT, 0)
	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachSyscallCloseEntry,
			bpf.AttachSyscallCloseExit},
		&connEventList,
		nil,
		nil)
	fmt.Println("Start Send Http Request")
	sendTestRequest(t, SendTestHttpRequestOptions{disableKeepAlived: true})

	time.Sleep(1 * time.Second)
	if len(connEventList) == 0 {
		t.Fatalf("no conn event!")
	}
	connectEvent := findInterestedConnEvent(t, connEventList, FindInterestedConnEventOptions{
		findByRemotePort: true,
		findByConnType:   true,
		remotePort:       80,
		connType:         bpf.AgentConnTypeTKClose,
		throw:            true})[0]
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
	StartEchoTcpServerAndWait()
	connEventList := make([]bpf.AgentConnEvtT, 0)

	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallAcceptEntry,
			bpf.AttachSyscallAcceptExit,
		},
		&connEventList,
		nil,
		nil)
	// ip, _ := common.GetIPAddrByInterfaceName("eth0")
	ip := "127.0.0.1"
	WriteToEchoTcpServerAndReadResponse(ip+":"+fmt.Sprint(echoTcpServerPort), "hello\n", true)
	time.Sleep(1 * time.Second)
	if len(connEventList) == 0 {
		t.Fatalf("no conn event!")
	}

	connectEvent := findInterestedConnEvent(t, connEventList, FindInterestedConnEventOptions{
		findByLocalPort: true,
		findByConnType:  true,
		localPort:       uint16(echoTcpServerPort),
		connType:        bpf.AgentConnTypeTKConnect,
		throw:           true})[0]
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

func TestRead(t *testing.T) {
	StartEchoTcpServerAndWait()
	connEventList := make([]bpf.AgentConnEvtT, 0)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	var connManager *conn.ConnManager = conn.InitConnManager()
	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachSyscallReadEntry,
			bpf.AttachSyscallReadExit,
			bpf.AttachKProbeSecuritySocketRecvmsgEntry,
		},
		&connEventList,
		&syscallEventList,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		})

	ip := "127.0.0.1"
	sendMsg := "GET hello\n"
	WriteToEchoTcpServerAndReadResponse(ip+":"+fmt.Sprint(echoTcpServerPort), sendMsg, true)
	time.Sleep(500 * time.Millisecond)

	assert.NotEmpty(t, syscallEventList)
	syscallEvents := findInterestedSyscallEvents(t, syscallEventList, FindInterestedSyscallEventOptions{
		findByRemotePort: true,
		remotePort:       uint16(echoTcpServerPort),
		connEventList:    connEventList,
	})
	syscallEvent := syscallEvents[0]
	conn := connManager.FindConnection4(syscallEvent.SyscallEvent.Ke.ConnIdS.TgidFd)
	AssertSyscallEventData(t, syscallEvent, SyscallDataEventAssertConditions{
		connIdDirect:          bpf.AgentTrafficDirectionTKIngress,
		pid:                   uint64(os.Getpid()),
		fd:                    uint32(conn.TgidFd),
		funcName:              "syscall",
		dataLen:               uint32(len(sendMsg)),
		seq:                   1,
		step:                  bpf.AgentStepTSYSCALL_IN,
		tsAssertFunction:      func(u uint64) bool { return u > 0 },
		bufSizeAssertFunction: func(u uint32) bool { return u == uint32(len(sendMsg)) },
		bufAssertFunction:     func(b []byte) bool { return string(b) == sendMsg },
	})
}

func TestWrite(t *testing.T) {
	StartEchoTcpServerAndWait()
	connEventList := make([]bpf.AgentConnEvtT, 0)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	var connManager *conn.ConnManager = conn.InitConnManager()
	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachSyscallWriteEntry,
			bpf.AttachSyscallWriteExit,
			bpf.AttachKProbeSecuritySocketSendmsgEntry,
		},
		&connEventList,
		&syscallEventList,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		})

	ip := "127.0.0.1"
	sendMsg := "GET hello\n"
	WriteToEchoTcpServerAndReadResponse(ip+":"+fmt.Sprint(echoTcpServerPort), sendMsg, true)
	time.Sleep(500 * time.Millisecond)

	assert.NotEmpty(t, syscallEventList)
	syscallEvents := findInterestedSyscallEvents(t, syscallEventList, FindInterestedSyscallEventOptions{
		findByRemotePort: true,
		remotePort:       uint16(echoTcpServerPort),
		connEventList:    connEventList,
	})
	syscallEvent := syscallEvents[0]
	conn := connManager.FindConnection4(syscallEvent.SyscallEvent.Ke.ConnIdS.TgidFd)
	AssertSyscallEventData(t, syscallEvent, SyscallDataEventAssertConditions{
		connIdDirect:          bpf.AgentTrafficDirectionTKEgress,
		pid:                   uint64(os.Getpid()),
		fd:                    uint32(conn.TgidFd),
		funcName:              "syscall",
		dataLen:               uint32(len(sendMsg)),
		seq:                   1,
		step:                  bpf.AgentStepTSYSCALL_OUT,
		tsAssertFunction:      func(u uint64) bool { return u > 0 },
		bufSizeAssertFunction: func(u uint32) bool { return u == uint32(len(sendMsg)) },
		bufAssertFunction:     func(b []byte) bool { return string(b) == sendMsg },
	})
}

func StartEchoTcpServerAndWait() {
	startCompleted := make(chan net.Listener)
	go StartEchoTcpServer(startCompleted)
	listener := <-startCompleted
	addr := listener.Addr().String()
	echoTcpServerPort, _ = strconv.Atoi(addr[strings.LastIndex(addr, ":")+1:])
	fmt.Println("Start Echo Server Completed! Listening Port is: ", echoTcpServerPort)
}

func WriteToEchoTcpServerAndReadResponse(server string, message string, readResponse bool) {

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

var echoTcpServerPort int = 10266

func StartEchoTcpServer(startCompleted chan net.Listener) {

	// obtain the port and prefix via program arguments
	port := ":0"
	prefix := ""

	// create a tcp listener on the given port
	listener, err := net.Listen("tcp4", port)
	if err != nil {
		fmt.Println("failed to create listener, err:", err)
		os.Exit(1)
	}
	defer listener.Close()
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
		line := fmt.Sprintf("%s%s", prefix, bytes)
		fmt.Printf("response: %s", line)
		conn.Write([]byte(line))
	}
}
