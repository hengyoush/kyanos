package agent_test

import (
	"bufio"
	"container/list"
	"errors"
	"fmt"
	"io"
	"kyanos/agent"
	"kyanos/agent/compatible"
	"kyanos/agent/conn"
	"kyanos/bpf"
	"kyanos/cmd"
	"kyanos/common"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/jefurry/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func StartAgent(bpfAttachFunctions []bpf.AttachBpfProgFunction,
	connEventList *[]bpf.AgentConnEvtT,
	syscallEventList *[]bpf.SyscallEventData,
	kernEventList *[]bpf.AgentKernEvt,
	connManagerInitHook func(*conn.ConnManager),
	agentStopper chan os.Signal) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func(pid int) {
		cmd.FilterPid = int64(pid)
		cmd.DefaultLogLevel = int32(logrus.DebugLevel)
		cmd.Debug = true
		cmd.InitLog()
		agent.SetupAgent(agent.AgentOptions{
			Stopper: agentStopper,
			LoadBpfProgramFunction: func(objs interface{}) *list.List {
				progs := list.New()
				for _, each := range bpfAttachFunctions {
					if each != nil {
						progs.PushBack(each(objs))
					}
				}
				return progs
			},
			CustomSyscallEventHook: func(evt *bpf.SyscallEventData) {
				if syscallEventList != nil {
					*syscallEventList = append(*syscallEventList, *evt)
				}
			},
			InitCompletedHook: func() {
				wg.Done()
			},
			CustomConnEventHook: func(evt *bpf.AgentConnEvtT) {
				if connEventList != nil {
					*connEventList = append(*connEventList, *evt)
				}
			},
			CustomKernEventHook: func(evt *bpf.AgentKernEvt) {
				if kernEventList != nil {
					*kernEventList = append(*kernEventList, *evt)
				}
			},
			ConnManagerInitHook: connManagerInitHook,
		})
	}(os.Getpid())

	wg.Wait()
}

type ConnEventAssertions struct {
	expectPid                  uint32
	expectLocalIp              string
	expectLocalAddrFamily      uint16
	expectLocalPort            int
	expectProtocol             bpf.AgentTrafficProtocolT
	expectRemoteIp             string
	expectRemoteFamily         uint16
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
	localIp := string(common.BytesToNetIP(connectEvent.ConnInfo.Laddr.In6.Sin6Addr.In6U.U6Addr8[:], false))
	if expectLocalIp != "" && localIp != expectLocalIp {
		t.Fatalf("Local IP Incorrect: %s != %s", localIp, expectLocalIp)
	}
	localAddr := connectEvent.ConnInfo.Laddr
	localAddrFamily := localAddr.In6.Sin6Family
	expectLocalAddrFamily := assert.expectLocalAddrFamily
	if expectLocalAddrFamily >= 0 && expectLocalAddrFamily != uint16(localAddrFamily) {
		t.Fatalf("LocalAddr Family Incorrect: %d != %d", localAddrFamily, expectLocalAddrFamily)
	}
	localPort := localAddr.In6.Sin6Port
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
	remoteIp := string(common.BytesToNetIP(remoteAddr.In6.Sin6Addr.In6U.U6Addr8[:], false))
	expectRemoteIp := assert.expectRemoteIp
	if expectRemoteIp != "" && expectRemoteIp != remoteIp {
		t.Fatalf("Remote IP Incorrect: %s != %s", remoteIp, expectRemoteIp)
	}
	remoteAddrFamily := remoteAddr.In6.Sin6Family
	expectRemoteFamily := assert.expectRemoteFamily
	if expectRemoteFamily >= 0 && expectRemoteFamily != uint16(remoteAddrFamily) {
		t.Fatalf("RemoteAddr Family Incorrect: %d != %d", remoteAddrFamily, expectRemoteFamily)
	}
	remotePort := remoteAddr.In6.Sin6Port
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

type KernDataEventAssertConditions struct {
	ignoreConnIdDirect bool
	direct             int
	ignorePid          bool
	pid                uint64
	ignoreFd           bool
	fd                 uint32
	ignoreFuncName     bool
	funcName           string
	ignoreDataLen      bool
	dataLen            uint32
	dataLenAssertFunc  func(uint32) bool
	ignoreSeq          bool
	seq                uint64
	ignoreStep         bool
	step               bpf.AgentStepT
	tsAssertFunction   func(uint64) bool
}

type SyscallDataEventAssertConditions struct {
	KernDataEventAssertConditions
	bufSizeAssertFunction func(uint32) bool
	bufAssertFunction     func([]byte) bool
}

func AssertKernEvent(t *testing.T, kernEvt *bpf.AgentKernEvt, conditions KernDataEventAssertConditions) {
	connId := kernEvt.ConnIdS
	if !conditions.ignoreConnIdDirect {
		assert.Equal(t, conditions.direct == Egress, kernEvt.Step <= bpf.AgentStepTNIC_IN)
	}
	pid := connId.TgidFd >> 32
	if !conditions.ignorePid {
		assert.Equal(t, conditions.pid, pid)
	}
	fd := uint32(connId.TgidFd)
	if !conditions.ignoreFd {
		assert.Equal(t, conditions.fd, fd)
	}
	funcName := common.Int8ToStr(kernEvt.FuncName[:])
	if !conditions.ignoreFuncName {
		assert.True(t, commonPrefixLength(funcName, conditions.funcName) >= len(conditions.funcName)-2)
	}
	dataLen := kernEvt.Len
	if !conditions.ignoreDataLen {
		assert.Equal(t, uint64(conditions.dataLen), uint64(dataLen))
	}

	if conditions.dataLenAssertFunc != nil {
		assert.True(t, conditions.dataLenAssertFunc(dataLen))
	}
	seq := kernEvt.Seq
	if !conditions.ignoreSeq {
		assert.Equal(t, conditions.seq, seq)
	}
	step := kernEvt.Step
	if !conditions.ignoreStep {
		assert.Equal(t, conditions.step, step)
	}

	ts := kernEvt.Ts
	if conditions.tsAssertFunction != nil {
		assert.True(t, conditions.tsAssertFunction(ts))
	}
}

func AssertSyscallEventData(t *testing.T, event bpf.SyscallEventData, conditions SyscallDataEventAssertConditions) {
	kernEvt := event.SyscallEvent.Ke
	AssertKernEvent(t, &kernEvt, conditions.KernDataEventAssertConditions)
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

var Egress int = 0
var Ingress int = 1

type FindInterestedKernEventOptions struct {
	findByRemotePort       bool
	remotePort             uint16
	findByLocalPort        bool
	localPort              uint16
	findDataLenGtZeroEvent bool
	findByDirect           bool
	direct                 int // 0-出 1-入
	findByFuncName         bool
	funcName               string
	throw                  bool
	findByStep             bool
	step                   bpf.AgentStepT

	connEventList []bpf.AgentConnEvtT
}

var CONN_EVENT_NOT_FOUND bpf.AgentConnEvtT = bpf.AgentConnEvtT{}

func findInterestedConnEvent(t *testing.T, connEventList []bpf.AgentConnEvtT, options FindInterestedConnEventOptions) []bpf.AgentConnEvtT {
	t.Helper()
	resultList := make([]bpf.AgentConnEvtT, 0)
	for _, connEvent := range connEventList {
		if options.findByRemotePort && options.remotePort != connEvent.ConnInfo.Raddr.In6.Sin6Port {
			continue
		}
		if options.findByLocalPort && options.localPort != connEvent.ConnInfo.Laddr.In6.Sin6Port {
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
		if options.findByRemotePort && connectEvent.ConnInfo.Raddr.In6.Sin6Port != options.remotePort {
			continue
		}
		if options.findByLocalPort && connectEvent.ConnInfo.Laddr.In6.Sin6Port != options.localPort {
			continue
		}
		resultList = append(resultList, each)
	}
	if options.throw && len(resultList) == 0 {
		t.Fatalf("no syscall event found for: %v", options)
	}
	return resultList
}

func findInterestedKernEvents(t *testing.T, kernEventList []bpf.AgentKernEvt, options FindInterestedKernEventOptions) []bpf.AgentKernEvt {
	t.Helper()
	resultList := make([]bpf.AgentKernEvt, 0)
	for _, each := range kernEventList {
		connectEvents := findInterestedConnEvent(t, options.connEventList, FindInterestedConnEventOptions{
			findByTgidFd:   true,
			findByConnType: true,
			tgidFd:         each.ConnIdS.TgidFd,
			connType:       bpf.AgentConnTypeTKConnect,
			throw:          false,
		})
		if len(connectEvents) == 0 {
			continue
		}
		connectEvent := connectEvents[0]
		if options.findByRemotePort && connectEvent.ConnInfo.Raddr.In6.Sin6Port != options.remotePort {
			continue
		}
		if options.findByLocalPort && connectEvent.ConnInfo.Laddr.In6.Sin6Port != options.localPort {
			continue
		}
		if options.findDataLenGtZeroEvent && each.Len == 0 {
			continue
		}
		if options.findByDirect && (options.direct == 0) != (each.Step <= bpf.AgentStepTNIC_OUT) {
			continue
		}
		eventFuncName := common.Int8ToStr(each.FuncName[:])
		if options.findByFuncName && commonPrefixLength(eventFuncName, options.funcName) < len(options.funcName)-2 {
			continue
		}
		if options.findByStep && each.Step != options.step {
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
	targetUrl         string
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
	req, err := http.NewRequest("GET", options.targetUrl, nil)
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

func StartEchoTcpServerAndWait() {
	startCompleted := make(chan net.Listener)
	go StartEchoTcpServer(startCompleted)
	listener := <-startCompleted
	addr := listener.Addr().String()
	echoTcpServerPort, _ = strconv.Atoi(addr[strings.LastIndex(addr, ":")+1:])
	fmt.Println("Start Echo Server Completed! Listening Port is: ", echoTcpServerPort)
}

type WriteSyscallType int
type ReadSyscallType int

const (
	Write WriteSyscallType = iota
	SentTo
	Writev
	Sendmsg
)

const (
	Read ReadSyscallType = iota
	RecvFrom
	Readv
	Recvmsg
)

type WriteToEchoServerOptions struct {
	t                     *testing.T
	server                string
	message               string
	messageSlice          []string
	readResponse          bool
	writeSyscall          WriteSyscallType
	readSyscall           ReadSyscallType
	readBufSizeSlice      []int
	useNonBlockingSoscket bool
}

func WriteToEchoTcpServerAndReadResponse(options WriteToEchoServerOptions) {
	connection, fd, _ := getConnectionAndFdToRemoteServer(options.server)
	defer connection.Close()
	if options.useNonBlockingSoscket {
		syscall.SetNonblock(int(fd), true)
	} else {
		syscall.SetNonblock(int(fd), false)
	}
	switch options.writeSyscall {
	case Write:
		syscall.Write(int(fd), []byte(options.message))
	case SentTo:
		syscall.Sendto(int(fd), []byte(options.message), 0, nil)
	case Writev:
		var iovecs [][]byte = make([][]byte, 0)
		for _, each := range options.messageSlice {
			iovecs = append(iovecs, []byte(each))
		}
		unix.Writev(int(fd), iovecs)
	case Sendmsg:
		var iovecs [][]byte = make([][]byte, 0)
		for _, each := range options.messageSlice {
			iovecs = append(iovecs, []byte(each))
		}
		unix.SendmsgBuffers(int(fd), iovecs, nil, nil, 0)

	default:
		options.t.Fatal("write syscall invalid")
	}
	if options.readResponse {
		readBytes := make([]byte, 1000)
		switch options.readSyscall {
		case Read:
			for {
				_, err := syscall.Read(int(fd), readBytes)
				if err == nil {
					break
				} else if !errors.Is(err, syscall.EAGAIN) {
					fmt.Printf("Read from socket failed: %v\n", err)
				}
			}

		case RecvFrom:
			for {
				_, _, err := syscall.Recvfrom(int(fd), readBytes, 0)
				if err == nil {
					break
				} else if !errors.Is(err, syscall.EAGAIN) {
					fmt.Printf("RecvFrom from socket failed: %v\n", err)
				}
			}
		case Readv:
			var iovecs [][]byte = make([][]byte, 0)
			for _, each := range options.readBufSizeSlice {
				iovecs = append(iovecs, make([]byte, each))
			}
			for {
				_, err := unix.Readv(int(fd), iovecs)
				if err == nil {
					break
				} else if !errors.Is(err, syscall.EAGAIN) {
					fmt.Printf("Readv from socket failed: %v\n", err)
				}
			}
		case Recvmsg:
			var iovecs [][]byte = make([][]byte, 0)
			for _, each := range options.readBufSizeSlice {
				iovecs = append(iovecs, make([]byte, each))
			}
			for {
				_, _, _, _, err := unix.RecvmsgBuffers(int(fd), iovecs, nil, 0)
				if err == nil {
					break
				} else if !errors.Is(err, syscall.EAGAIN) {
					fmt.Printf("Readv from socket failed: %v\n", err)
				}
			}
		}
		fmt.Printf("Read  from conn: %s\n", string(readBytes))
	}
}
func getConnectionAndFdToRemoteServer(server string) (net.Conn, int64, error) {
	connection, err := net.Dial("tcp", server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法连接到服务器 %s: %v\n", server, err)
		return nil, 0, err
	}
	tcpConn := connection.(*net.TCPConn)
	tcpConnV := reflect.ValueOf(*tcpConn)
	fd := tcpConnV.FieldByName("conn").FieldByName("fd").Elem().FieldByName("pfd").FieldByName("Sysfd").Int()
	return connection, fd, nil
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

type MySignal struct {
}

func (MySignal) String() string {
	return "MySignal"
}
func (MySignal) Signal() {

}

// 计算两个字符串的公共前缀长度
func commonPrefixLength(s1, s2 string) int {
	minLen := min(len(s1), len(s2))
	for i := 0; i < minLen; i++ {
		// 比较每个字符，找到第一个不相同的字符
		if s1[i] != s2[i] {
			return i
		}
	}
	return minLen
}

// 辅助函数，返回两个整数中的最小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// func MayBeXdpFunction(defaultFunc bpf.AttachBpfProgFunction) bpf.AttachBpfProgFunction {
// 	if !compatilbeMode {
// 		return bpf.AttachXdp
// 	} else {
// 		return defaultFunc
// 	}
// }

// var compatilbeMode bool = false

// func SetCompatibleMode(b bool) {
// 	compatilbeMode = b
// }

func ApplyKernelVersionFunctions(t *testing.T, step bpf.AgentStepT, programs any) link.Link {
	v := compatible.GetCurrentKernelVersion()
	if step == bpf.AgentStepTNIC_IN {
		if v.SupportCapability(compatible.SupportXDP) {
			l, err := bpf.AttachXdp(programs)
			if err != nil {
				t.Fatal(err)
			} else {
				return l
			}
		} else {
			t.FailNow()
		}
	}
	functions, ok := v.InstrumentFunctions[step]
	if !ok {
		t.FailNow()
	}
	for idx, function := range functions {
		var err error
		var l link.Link
		if function.IsKprobe() {
			l, err = bpf.Kprobe(function.GetKprobeName(), bpf.GetProgram(programs, function.BPFGoProgName))
		} else if function.IsTracepoint() {
			l, err = bpf.Tracepoint(function.GetTracepointGroupName(), function.GetTracepointName(),
				bpf.GetProgram(programs, function.BPFGoProgName))
		} else if function.IsKRetprobe() {
			l, err = bpf.Kretprobe(function.GetKprobeName(), bpf.GetProgram(programs, function.BPFGoProgName))
		} else {
			panic(fmt.Sprintf("invalid program type: %v", function))
		}
		if err != nil {
			if idx == len(functions)-1 {
				log.Fatalf("Attach failed: %v, functions: %v", err, functions)
			}
		} else {
			return l
		}
	}
	t.FailNow()
	return nil
}
