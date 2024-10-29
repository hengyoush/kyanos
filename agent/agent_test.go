package agent_test

import (
	"fmt"
	ac "kyanos/agent/common"
	"kyanos/agent/compatible"
	"kyanos/agent/conn"
	"kyanos/bpf"
	"kyanos/common"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
)

var customAgentOptions ac.AgentOptions = ac.AgentOptions{}

func TestMain(m *testing.M) {
	// call flag.Parse() here if TestMain uses flags]
	customAgentOptions = ac.AgentOptions{}
	retCode := m.Run()
	tearDown()
	os.Exit(retCode)
}

func tearDown() {
	// Do something here.
	time.Sleep(1 * time.Second)
	fmt.Println("teardown!")
}

func TestConnectSyscall(t *testing.T) {
	connEventList := make([]bpf.AgentConnEvtT, 0)
	agentStopper := make(chan os.Signal, 1)
	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
		},
		&connEventList,
		nil,
		nil,
		nil,
		agentStopper)
	defer func() {
		agentStopper <- MySignal{}
	}()
	fmt.Println("Start Send Http Request")
	sendTestHttpRequest(t, SendTestHttpRequestOptions{disableKeepAlived: true, targetUrl: "http://www.baidu.com"})

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

func TestCloseSyscall(t *testing.T) {
	connEventList := make([]bpf.AgentConnEvtT, 0)
	agentStopper := make(chan os.Signal, 1)
	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachSyscallCloseEntry,
			bpf.AttachSyscallCloseExit},
		&connEventList,
		nil,
		nil,
		nil, agentStopper)
	defer func() {
		agentStopper <- MySignal{}
	}()
	fmt.Println("Start Send Http Request")
	sendTestHttpRequest(t, SendTestHttpRequestOptions{disableKeepAlived: true, targetUrl: "http://www.baidu.com"})

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
	agentStopper := make(chan os.Signal, 1)

	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallAcceptEntry,
			bpf.AttachSyscallAcceptExit,
		},
		&connEventList,
		nil,
		nil,
		nil, agentStopper)
	defer func() {
		agentStopper <- MySignal{}
	}()
	// ip, _ := common.GetIPAddrByInterfaceName("eth0")
	ip := "127.0.0.1"
	WriteToEchoTcpServerAndReadResponse(WriteToEchoServerOptions{
		t:            t,
		server:       ip + ":" + fmt.Sprint(echoTcpServerPort),
		message:      "hello\n",
		readResponse: true,
		writeSyscall: Write,
		readSyscall:  Read,
	})
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

func TestExistedConn(t *testing.T) {
	StartEchoTcpServerAndWait()
	ip := "127.0.0.1"
	sendMsg := "GET TestRead\n"
	connection := WriteToEchoTcpServerAndReadResponse(WriteToEchoServerOptions{
		t:              t,
		server:         ip + ":" + fmt.Sprint(echoTcpServerPort),
		message:        sendMsg,
		readResponse:   true,
		writeSyscall:   Write,
		readSyscall:    Read,
		keepConnection: true,
	})
	// established conn and write data before start kyanos

	connEventList := make([]bpf.AgentConnEvtT, 0)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	kernEventList := make([]bpf.AgentKernEvt, 0)
	var connManager *conn.ConnManager = conn.InitConnManager()
	agentStopper := make(chan os.Signal)
	StartAgent(
		nil,
		&connEventList,
		&syscallEventList,
		&kernEventList,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		}, agentStopper)
	defer func() {
		agentStopper <- MySignal{}
	}()
	// then write data
	WriteToEchoTcpServerAndReadResponse(WriteToEchoServerOptions{
		t:                 t,
		server:            ip + ":" + fmt.Sprint(echoTcpServerPort),
		message:           sendMsg,
		readResponse:      true,
		writeSyscall:      Write,
		readSyscall:       Read,
		keepConnection:    true,
		existedConnection: connection,
	})
	WriteToEchoTcpServerAndReadResponse(WriteToEchoServerOptions{
		t:                 t,
		server:            ip + ":" + fmt.Sprint(echoTcpServerPort),
		message:           sendMsg,
		readResponse:      true,
		writeSyscall:      Write,
		readSyscall:       Read,
		keepConnection:    true,
		existedConnection: connection,
	})
	time.Sleep(1500 * time.Millisecond)

	assert.True(t, len(syscallEventList) > 0)
	assert.True(t, len(connEventList) > 0)
	assert.True(t, len(kernEventList) > 0)
	assert.True(t, len(findInterestedKernEvents(t, kernEventList, FindInterestedKernEventOptions{
		connEventList: connEventList,
		findByStep:    true,
		step:          bpf.AgentStepTIP_OUT,
	})) > 0)
	assert.True(t, len(findInterestedKernEvents(t, kernEventList, FindInterestedKernEventOptions{
		connEventList: connEventList,
		findByStep:    true,
		step:          bpf.AgentStepTQDISC_OUT,
	})) > 0)
	assert.True(t, len(findInterestedKernEvents(t, kernEventList, FindInterestedKernEventOptions{
		connEventList: connEventList,
		findByStep:    true,
		step:          bpf.AgentStepTDEV_OUT,
	})) > 0)
	assert.True(t, len(findInterestedKernEvents(t, kernEventList, FindInterestedKernEventOptions{
		connEventList: connEventList,
		findByStep:    true,
		step:          bpf.AgentStepTDEV_IN,
	})) > 0)
	assert.True(t, len(findInterestedKernEvents(t, kernEventList, FindInterestedKernEventOptions{
		connEventList: connEventList,
		findByStep:    true,
		step:          bpf.AgentStepTIP_IN,
	})) > 0)
	assert.True(t, len(findInterestedKernEvents(t, kernEventList, FindInterestedKernEventOptions{
		connEventList: connEventList,
		findByStep:    true,
		step:          bpf.AgentStepTTCP_IN,
	})) > 0)
	assert.True(t, len(findInterestedKernEvents(t, kernEventList, FindInterestedKernEventOptions{
		connEventList: connEventList,
		findByStep:    true,
		step:          bpf.AgentStepTUSER_COPY,
	})) > 0)
}

func TestRead(t *testing.T) {
	StartEchoTcpServerAndWait()
	connEventList := make([]bpf.AgentConnEvtT, 0)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	agentStopper := make(chan os.Signal)
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
		nil,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		}, agentStopper)

	defer func() {
		agentStopper <- MySignal{}
	}()
	ip := "127.0.0.1"
	sendMsg := "GET TestRead\n"
	WriteToEchoTcpServerAndReadResponse(WriteToEchoServerOptions{
		t:            t,
		server:       ip + ":" + fmt.Sprint(echoTcpServerPort),
		message:      sendMsg,
		readResponse: true,
		writeSyscall: Write,
		readSyscall:  Read,
	})
	time.Sleep(500 * time.Millisecond)

	assert.NotEmpty(t, syscallEventList)
	syscallEvents := findInterestedSyscallEvents(t, syscallEventList, FindInterestedSyscallEventOptions{
		findByRemotePort: true,
		remotePort:       uint16(echoTcpServerPort),
		connEventList:    connEventList,
	})
	syscallEvent := syscallEvents[0]
	conn := connManager.FindConnection4Exactly(syscallEvent.SyscallEvent.Ke.ConnIdS.TgidFd)
	AssertSyscallEventData(t, syscallEvent, SyscallDataEventAssertConditions{
		KernDataEventAssertConditions: KernDataEventAssertConditions{
			direct:           Ingress,
			pid:              uint64(os.Getpid()),
			fd:               uint32(conn.TgidFd),
			funcName:         "syscall",
			ignoreFuncName:   true,
			dataLen:          uint32(len(sendMsg)),
			seq:              1,
			step:             bpf.AgentStepTSYSCALL_IN,
			tsAssertFunction: func(u uint64) bool { return u > 0 },
		},
		bufSizeAssertFunction: func(u uint32) bool { return u == uint32(len(sendMsg)) },
		bufAssertFunction:     func(b []byte) bool { return string(b) == sendMsg },
	})
}

func TestRecvFrom(t *testing.T) {
	StartEchoTcpServerAndWait()
	connEventList := make([]bpf.AgentConnEvtT, 0)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	var connManager *conn.ConnManager = conn.InitConnManager()
	agentStopper := make(chan os.Signal, 1)
	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachSyscallRecvfromEntry,
			bpf.AttachSyscallRecvfromExit,
			bpf.AttachKProbeSecuritySocketRecvmsgEntry,
		},
		&connEventList,
		&syscallEventList,
		nil,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		}, agentStopper)

	defer func() {
		agentStopper <- MySignal{}
	}()
	ip := "127.0.0.1"
	sendMsg := "GET TestRecvFrom\n"
	WriteToEchoTcpServerAndReadResponse(WriteToEchoServerOptions{
		t:            t,
		server:       ip + ":" + fmt.Sprint(echoTcpServerPort),
		message:      sendMsg,
		readResponse: true,
		writeSyscall: Write,
		readSyscall:  RecvFrom,
	})
	time.Sleep(500 * time.Millisecond)

	assert.NotEmpty(t, syscallEventList)
	syscallEvents := findInterestedSyscallEvents(t, syscallEventList, FindInterestedSyscallEventOptions{
		findByRemotePort: true,
		remotePort:       uint16(echoTcpServerPort),
		connEventList:    connEventList,
	})
	syscallEvent := syscallEvents[0]
	conn := connManager.FindConnection4Exactly(syscallEvent.SyscallEvent.Ke.ConnIdS.TgidFd)
	AssertSyscallEventData(t, syscallEvent, SyscallDataEventAssertConditions{
		KernDataEventAssertConditions: KernDataEventAssertConditions{
			direct:           Ingress,
			pid:              uint64(os.Getpid()),
			fd:               uint32(conn.TgidFd),
			funcName:         "syscall",
			ignoreFuncName:   true,
			dataLen:          uint32(len(sendMsg)),
			seq:              1,
			step:             bpf.AgentStepTSYSCALL_IN,
			tsAssertFunction: func(u uint64) bool { return u > 0 },
		},
		bufSizeAssertFunction: func(u uint32) bool { return u == uint32(len(sendMsg)) },
		bufAssertFunction:     func(b []byte) bool { return string(b) == sendMsg },
	})
}

func TestReadv(t *testing.T) {
	StartEchoTcpServerAndWait()
	connEventList := make([]bpf.AgentConnEvtT, 0)
	agentStopper := make(chan os.Signal, 1)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	var connManager *conn.ConnManager = conn.InitConnManager()
	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachSyscallReadvEntry,
			bpf.AttachSyscallReadvExit,
			bpf.AttachKProbeSecuritySocketRecvmsgEntry,
		},
		&connEventList,
		&syscallEventList,
		nil,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		}, agentStopper)

	defer func() {
		agentStopper <- MySignal{}
	}()
	ip := "127.0.0.1"
	sendMsg := "GET TestReadv\n"
	readBufSizeSlice := []int{len(sendMsg) / 2, len(sendMsg) - len(sendMsg)/2}
	WriteToEchoTcpServerAndReadResponse(WriteToEchoServerOptions{
		t:                t,
		server:           ip + ":" + fmt.Sprint(echoTcpServerPort),
		message:          sendMsg,
		readResponse:     true,
		writeSyscall:     Write,
		readSyscall:      Readv,
		readBufSizeSlice: readBufSizeSlice,
	})
	time.Sleep(500 * time.Millisecond)

	assert.NotEmpty(t, syscallEventList)
	syscallEvents := findInterestedSyscallEvents(t, syscallEventList, FindInterestedSyscallEventOptions{
		findByRemotePort: true,
		remotePort:       uint16(echoTcpServerPort),
		connEventList:    connEventList,
	})
	assert.Equal(t, len(readBufSizeSlice), len(syscallEvents))
	conn := connManager.FindConnection4Exactly(syscallEvents[0].SyscallEvent.Ke.ConnIdS.TgidFd)
	seq := uint64(1)
	for index, syscallEvent := range syscallEvents {
		AssertSyscallEventData(t, syscallEvent, SyscallDataEventAssertConditions{
			KernDataEventAssertConditions: KernDataEventAssertConditions{
				direct:           Ingress,
				pid:              uint64(os.Getpid()),
				fd:               uint32(conn.TgidFd),
				funcName:         "syscall",
				ignoreFuncName:   true,
				dataLen:          uint32(readBufSizeSlice[index]),
				seq:              seq,
				step:             bpf.AgentStepTSYSCALL_IN,
				tsAssertFunction: func(u uint64) bool { return u > 0 },
			},
			bufSizeAssertFunction: func(u uint32) bool { return u == uint32(readBufSizeSlice[index]) },
			bufAssertFunction:     func(b []byte) bool { return string(b) == sendMsg[seq-1:int(seq)-1+readBufSizeSlice[index]] },
		})
		seq += uint64(readBufSizeSlice[index])
	}
}

func TestRecvmsg(t *testing.T) {
	StartEchoTcpServerAndWait()
	connEventList := make([]bpf.AgentConnEvtT, 0)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	agentStopper := make(chan os.Signal, 1)
	var connManager *conn.ConnManager = conn.InitConnManager()
	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachSyscallRecvMsgEntry,
			bpf.AttachSyscallRecvMsgExit,
			bpf.AttachKProbeSecuritySocketRecvmsgEntry,
		},
		&connEventList,
		&syscallEventList,
		nil,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		}, agentStopper)
	defer func() {
		agentStopper <- MySignal{}
	}()

	ip := "127.0.0.1"
	sendMsg := "GET TestRecvmsg\n"
	readBufSizeSlice := []int{len(sendMsg) / 2, len(sendMsg) - len(sendMsg)/2}
	WriteToEchoTcpServerAndReadResponse(WriteToEchoServerOptions{
		t:                t,
		server:           ip + ":" + fmt.Sprint(echoTcpServerPort),
		message:          sendMsg,
		readResponse:     true,
		writeSyscall:     Write,
		readSyscall:      Recvmsg,
		readBufSizeSlice: readBufSizeSlice,
	})
	time.Sleep(500 * time.Millisecond)

	assert.NotEmpty(t, syscallEventList)
	syscallEvents := findInterestedSyscallEvents(t, syscallEventList, FindInterestedSyscallEventOptions{
		findByRemotePort: true,
		remotePort:       uint16(echoTcpServerPort),
		connEventList:    connEventList,
	})
	assert.Equal(t, len(readBufSizeSlice), len(syscallEvents))
	conn := connManager.FindConnection4Exactly(syscallEvents[0].SyscallEvent.Ke.ConnIdS.TgidFd)
	seq := uint64(1)
	for index, syscallEvent := range syscallEvents {
		AssertSyscallEventData(t, syscallEvent, SyscallDataEventAssertConditions{
			KernDataEventAssertConditions: KernDataEventAssertConditions{
				direct:           Ingress,
				pid:              uint64(os.Getpid()),
				fd:               uint32(conn.TgidFd),
				ignoreFuncName:   true,
				funcName:         "syscall",
				dataLen:          uint32(readBufSizeSlice[index]),
				seq:              seq,
				step:             bpf.AgentStepTSYSCALL_IN,
				tsAssertFunction: func(u uint64) bool { return u > 0 },
			},
			bufSizeAssertFunction: func(u uint32) bool { return u == uint32(readBufSizeSlice[index]) },
			bufAssertFunction:     func(b []byte) bool { return string(b) == sendMsg[seq-1:int(seq)-1+readBufSizeSlice[index]] },
		})
		seq += uint64(readBufSizeSlice[index])
	}
}

func TestSslRead(t *testing.T) {
	connEventList := make([]bpf.AgentConnEvtT, 0)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	sslEventList := make([]bpf.SslData, 0)
	var connManager *conn.ConnManager = conn.InitConnManager()
	agentStopper := make(chan os.Signal, 1)
	StartAgent0(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachKProbeSecuritySocketSendmsgEntry,
		},
		&connEventList,
		&syscallEventList,
		&sslEventList,
		nil,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		}, agentStopper, false)

	defer func() {
		agentStopper <- MySignal{}
	}()
	_, cmd, _ := curlHTTPSRequest("https://www.baidu.com:443", "GET", nil, "")
	time.Sleep(500 * time.Millisecond)

	assert.NotEmpty(t, sslEventList)
	syscallEvents := findInterestedSslEvents(t, sslEventList, FindInterestedSyscallEventOptions{
		findByRemotePort: true,
		remotePort:       443,
		connEventList:    connEventList,
		findByPid:        true,
		pid:              cmd.Process.Pid,
		findByStep:       true,
		step:             bpf.AgentStepTSSL_IN,
	})
	sslEvent := syscallEvents[0]
	conn := connManager.FindConnection4Exactly(sslEvent.SslEventHeader.Ke.ConnIdS.TgidFd)
	AssertSslEventData(t, sslEvent, SyscallDataEventAssertConditions{
		KernDataEventAssertConditions: KernDataEventAssertConditions{
			direct:           Egress,
			pid:              uint64(cmd.Process.Pid),
			fd:               uint32(conn.TgidFd),
			ignoreFuncName:   true,
			ignoreDataLen:    true,
			seq:              1,
			step:             bpf.AgentStepTSSL_OUT,
			tsAssertFunction: func(u uint64) bool { return u > 0 },
		},
		bufSizeAssertFunction: func(u uint32) bool { return u > 0 },
	})
}

func TestSslEventsCanRelatedToKernEvents(t *testing.T) {
	connEventList := make([]bpf.AgentConnEvtT, 0)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	sslEventList := make([]bpf.SslData, 0)
	kernEventList := make([]bpf.AgentKernEvt, 0)
	var connManager *conn.ConnManager = conn.InitConnManager()
	agentStopper := make(chan os.Signal, 1)
	StartAgent0(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachSyscallRecvfromEntry,
			bpf.AttachSyscallRecvfromExit,
			bpf.AttachSyscallReadEntry,
			bpf.AttachSyscallReadExit,
			bpf.AttachSyscallWriteEntry,
			bpf.AttachSyscallWriteExit,
			bpf.AttachKProbeSecuritySocketSendmsgEntry,
			bpf.AttachKProbeSecuritySocketRecvmsgEntry,
			func() link.Link {
				return ApplyKernelVersionFunctions(t, bpf.AgentStepTDEV_IN)
			},
			func() link.Link {
				return ApplyKernelVersionFunctions(t, bpf.AgentStepTUSER_COPY)
			},
			func() link.Link {
				return ApplyKernelVersionFunctions(t, bpf.AgentStepTIP_IN)
			},
			func() link.Link {
				return ApplyKernelVersionFunctions(t, bpf.AgentStepTTCP_IN)
			},
			func() link.Link {
				return ApplyKernelVersionFunctions(t, bpf.AgentStepTIP_OUT)
			},
			func() link.Link {
				return ApplyKernelVersionFunctions(t, bpf.AgentStepTDEV_OUT)
			},
			func() link.Link {
				return ApplyKernelVersionFunctions(t, bpf.AgentStepTQDISC_OUT)
			},
		},
		&connEventList,
		&syscallEventList,
		&sslEventList,
		&kernEventList,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		}, agentStopper, false)

	defer func() {
		agentStopper <- MySignal{}
	}()
	_, cmd, _ := curlHTTPSRequest("https://www.baidu.com:443", "GET", nil, "")
	time.Sleep(500 * time.Millisecond)
	sslEvents := findInterestedSslEvents(t, sslEventList, FindInterestedSyscallEventOptions{
		findByRemotePort: true,
		remotePort:       443,
		connEventList:    connEventList,
		findByPid:        true,
		pid:              cmd.Process.Pid,
		findByStep:       true,
		step:             bpf.AgentStepTSSL_OUT,
	})
	assert.True(t, len(sslEvents) > 0)
	sslEvent := sslEvents[0]
	conn := connManager.FindConnection4Exactly(sslEvent.SslEventHeader.Ke.ConnIdS.TgidFd)
	se := conn.StreamEvents
	sslOutEvents := se.FindSslEventsBySeqAndLen(bpf.AgentStepTSSL_OUT, 1, 1000)
	assert.True(t, len(sslOutEvents) > 0)
	sslInEvents := se.FindSslEventsBySeqAndLen(bpf.AgentStepTSSL_IN, 1, 10000)
	assert.True(t, len(sslInEvents) > 0)

	kernSeq := sslInEvents[0].KernSeq
	kernLen := sslInEvents[0].KernLen
	devinEvents := se.FindEventsBySeqAndLen(bpf.AgentStepTDEV_IN, kernSeq, kernLen)
	assert.True(t, len(devinEvents) > 0)
	ipinEvents := se.FindEventsBySeqAndLen(bpf.AgentStepTIP_IN, kernSeq, kernLen)
	assert.True(t, len(ipinEvents) > 0)
	usercopyEvents := se.FindEventsBySeqAndLen(bpf.AgentStepTUSER_COPY, kernSeq, kernLen)
	assert.True(t, len(usercopyEvents) > 0)
	syscallInEvents := se.FindEventsBySeqAndLen(bpf.AgentStepTSYSCALL_IN, kernSeq, kernLen)
	assert.True(t, len(syscallInEvents) > 0)
}

func TestSslWrite(t *testing.T) {
	connEventList := make([]bpf.AgentConnEvtT, 0)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	sslEventList := make([]bpf.SslData, 0)
	var connManager *conn.ConnManager = conn.InitConnManager()
	agentStopper := make(chan os.Signal, 1)
	StartAgent0(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachKProbeSecuritySocketSendmsgEntry,
		},
		&connEventList,
		&syscallEventList,
		&sslEventList,
		nil,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		}, agentStopper, false)

	defer func() {
		agentStopper <- MySignal{}
	}()
	_, cmd, _ := curlHTTPSRequest("https://www.baidu.com:443", "GET", nil, "")
	time.Sleep(500 * time.Millisecond)

	assert.NotEmpty(t, sslEventList)
	syscallEvents := findInterestedSslEvents(t, sslEventList, FindInterestedSyscallEventOptions{
		findByRemotePort: true,
		remotePort:       443,
		connEventList:    connEventList,
		findByPid:        true,
		pid:              cmd.Process.Pid,
		findByStep:       true,
		step:             bpf.AgentStepTSSL_OUT,
	})
	sslEvent := syscallEvents[0]
	conn := connManager.FindConnection4Exactly(sslEvent.SslEventHeader.Ke.ConnIdS.TgidFd)
	AssertSslEventData(t, sslEvent, SyscallDataEventAssertConditions{
		KernDataEventAssertConditions: KernDataEventAssertConditions{
			direct:           Egress,
			pid:              uint64(cmd.Process.Pid),
			fd:               uint32(conn.TgidFd),
			ignoreFuncName:   true,
			ignoreDataLen:    true,
			seq:              1,
			step:             bpf.AgentStepTSSL_OUT,
			tsAssertFunction: func(u uint64) bool { return u > 0 },
		},
		bufSizeAssertFunction: func(u uint32) bool { return u > 0 },
	})
}

func TestWrite(t *testing.T) {
	StartEchoTcpServerAndWait()
	connEventList := make([]bpf.AgentConnEvtT, 0)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	var connManager *conn.ConnManager = conn.InitConnManager()
	agentStopper := make(chan os.Signal, 1)
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
		nil,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		}, agentStopper)

	defer func() {
		agentStopper <- MySignal{}
	}()
	ip := "127.0.0.1"
	sendMsg := "GET TestWrite\n"
	WriteToEchoTcpServerAndReadResponse(WriteToEchoServerOptions{
		t:            t,
		server:       ip + ":" + fmt.Sprint(echoTcpServerPort),
		message:      sendMsg,
		readResponse: true,
		writeSyscall: Write,
		readSyscall:  Read,
	})
	time.Sleep(500 * time.Millisecond)

	assert.NotEmpty(t, syscallEventList)
	syscallEvents := findInterestedSyscallEvents(t, syscallEventList, FindInterestedSyscallEventOptions{
		findByRemotePort: true,
		remotePort:       uint16(echoTcpServerPort),
		connEventList:    connEventList,
	})
	syscallEvent := syscallEvents[0]
	conn := connManager.FindConnection4Exactly(syscallEvent.SyscallEvent.Ke.ConnIdS.TgidFd)
	AssertSyscallEventData(t, syscallEvent, SyscallDataEventAssertConditions{
		KernDataEventAssertConditions: KernDataEventAssertConditions{
			direct:           Egress,
			pid:              uint64(os.Getpid()),
			fd:               uint32(conn.TgidFd),
			funcName:         "syscall",
			ignoreFuncName:   true,
			dataLen:          uint32(len(sendMsg)),
			seq:              1,
			step:             bpf.AgentStepTSYSCALL_OUT,
			tsAssertFunction: func(u uint64) bool { return u > 0 },
		},
		bufSizeAssertFunction: func(u uint32) bool { return u == uint32(len(sendMsg)) },
		bufAssertFunction:     func(b []byte) bool { return string(b) == sendMsg },
	})
}

func TestSendto(t *testing.T) {
	StartEchoTcpServerAndWait()
	connEventList := make([]bpf.AgentConnEvtT, 0)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	var connManager *conn.ConnManager = conn.InitConnManager()
	agentStopper := make(chan os.Signal, 1)
	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachSyscallSendtoEntry,
			bpf.AttachSyscallSendtoExit,
			bpf.AttachKProbeSecuritySocketSendmsgEntry,
		},
		&connEventList,
		&syscallEventList,
		nil,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		}, agentStopper)
	defer func() {
		agentStopper <- MySignal{}
	}()

	ip := "127.0.0.1"
	sendMsg := "GET TestSendto\n"
	WriteToEchoTcpServerAndReadResponse(WriteToEchoServerOptions{
		t:            t,
		server:       ip + ":" + fmt.Sprint(echoTcpServerPort),
		message:      sendMsg,
		readResponse: true,
		writeSyscall: SentTo,
		readSyscall:  Read,
	})
	time.Sleep(500 * time.Millisecond)

	assert.NotEmpty(t, syscallEventList)
	syscallEvents := findInterestedSyscallEvents(t, syscallEventList, FindInterestedSyscallEventOptions{
		findByRemotePort: true,
		remotePort:       uint16(echoTcpServerPort),
		connEventList:    connEventList,
	})
	syscallEvent := syscallEvents[0]
	conn := connManager.FindConnection4Exactly(syscallEvent.SyscallEvent.Ke.ConnIdS.TgidFd)
	AssertSyscallEventData(t, syscallEvent, SyscallDataEventAssertConditions{
		KernDataEventAssertConditions: KernDataEventAssertConditions{
			direct:           Egress,
			pid:              uint64(os.Getpid()),
			fd:               uint32(conn.TgidFd),
			funcName:         "syscall",
			ignoreFuncName:   true,
			dataLen:          uint32(len(sendMsg)),
			seq:              1,
			step:             bpf.AgentStepTSYSCALL_OUT,
			tsAssertFunction: func(u uint64) bool { return u > 0 },
		},
		bufSizeAssertFunction: func(u uint32) bool { return u == uint32(len(sendMsg)) },
		bufAssertFunction:     func(b []byte) bool { return string(b) == sendMsg },
	})
}

func TestWritev(t *testing.T) {
	StartEchoTcpServerAndWait()
	connEventList := make([]bpf.AgentConnEvtT, 0)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	agentStopper := make(chan os.Signal, 1)
	var connManager *conn.ConnManager = conn.InitConnManager()
	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachSyscallWritevEntry,
			bpf.AttachSyscallWritevExit,
			bpf.AttachKProbeSecuritySocketSendmsgEntry,
		},
		&connEventList,
		&syscallEventList,
		nil,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		}, agentStopper)
	defer func() {
		agentStopper <- MySignal{}
	}()

	ip := "127.0.0.1"
	sendMessages := []string{"GET writevhellohellohellohello\n", "abchellohellohellohello\n"}
	WriteToEchoTcpServerAndReadResponse(WriteToEchoServerOptions{
		t:            t,
		server:       ip + ":" + fmt.Sprint(echoTcpServerPort),
		messageSlice: sendMessages,
		readResponse: true,
		writeSyscall: Writev,
		readSyscall:  Read,
	})
	time.Sleep(500 * time.Millisecond)

	assert.NotEmpty(t, syscallEventList)
	syscallEvents := findInterestedSyscallEvents(t, syscallEventList, FindInterestedSyscallEventOptions{
		findByRemotePort: true,
		remotePort:       uint16(echoTcpServerPort),
		connEventList:    connEventList,
	})
	assert.Equal(t, 2, len(syscallEvents))
	conn := connManager.FindConnection4Exactly(syscallEvents[0].SyscallEvent.Ke.ConnIdS.TgidFd)
	seq := uint64(1)
	for index, syscallEvent := range syscallEvents {
		AssertSyscallEventData(t, syscallEvent, SyscallDataEventAssertConditions{
			KernDataEventAssertConditions: KernDataEventAssertConditions{
				direct:           Egress,
				pid:              uint64(os.Getpid()),
				fd:               uint32(conn.TgidFd),
				funcName:         "syscall",
				ignoreFuncName:   true,
				dataLen:          uint32(len(sendMessages[index])),
				seq:              seq,
				step:             bpf.AgentStepTSYSCALL_OUT,
				tsAssertFunction: func(u uint64) bool { return u > 0 },
			},
			bufSizeAssertFunction: func(u uint32) bool { return u == uint32(len(sendMessages[index])) },
			bufAssertFunction:     func(b []byte) bool { return string(b) == sendMessages[index] },
		})
		seq += uint64(len(sendMessages[index]))
	}
}

func TestSendMsg(t *testing.T) {
	StartEchoTcpServerAndWait()
	connEventList := make([]bpf.AgentConnEvtT, 0)
	syscallEventList := make([]bpf.SyscallEventData, 0)
	var connManager *conn.ConnManager = conn.InitConnManager()
	agentStopper := make(chan os.Signal, 1)
	StartAgent(
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachSyscallSendMsgEntry,
			bpf.AttachSyscallSendMsgExit,
			bpf.AttachKProbeSecuritySocketSendmsgEntry,
		},
		&connEventList,
		&syscallEventList,
		nil,
		func(cm *conn.ConnManager) {
			*connManager = *cm
		}, agentStopper)
	defer func() {
		agentStopper <- MySignal{}
	}()

	ip := "127.0.0.1"
	sendMessages := []string{"GET sendmsghellohellohellohello\n", "aabchellohellohellohello\n"}
	WriteToEchoTcpServerAndReadResponse(WriteToEchoServerOptions{
		t:            t,
		server:       ip + ":" + fmt.Sprint(echoTcpServerPort),
		messageSlice: sendMessages,
		readResponse: true,
		writeSyscall: Sendmsg,
		readSyscall:  Read,
	})
	time.Sleep(500 * time.Millisecond)

	assert.NotEmpty(t, syscallEventList)
	syscallEvents := findInterestedSyscallEvents(t, syscallEventList, FindInterestedSyscallEventOptions{
		findByRemotePort: true,
		remotePort:       uint16(echoTcpServerPort),
		connEventList:    connEventList,
	})
	assert.Equal(t, 2, len(syscallEvents))
	conn := connManager.FindConnection4Exactly(syscallEvents[0].SyscallEvent.Ke.ConnIdS.TgidFd)
	seq := uint64(1)
	for index, syscallEvent := range syscallEvents {
		AssertSyscallEventData(t, syscallEvent, SyscallDataEventAssertConditions{
			KernDataEventAssertConditions: KernDataEventAssertConditions{direct: Egress,
				pid:              uint64(os.Getpid()),
				fd:               uint32(conn.TgidFd),
				ignoreFuncName:   true,
				funcName:         "syscall",
				dataLen:          uint32(len(sendMessages[index])),
				seq:              seq,
				step:             bpf.AgentStepTSYSCALL_OUT,
				tsAssertFunction: func(u uint64) bool { return u > 0 },
			},
			bufSizeAssertFunction: func(u uint32) bool { return u == uint32(len(sendMessages[index])) },
			bufAssertFunction:     func(b []byte) bool { return string(b) == sendMessages[index] },
		})
		seq += uint64(len(sendMessages[index]))
	}
}

func TestIpXmit(t *testing.T) {
	options := KernTestWithTcpEchoServerOptions{
		t,
		[]bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachSyscallWriteEntry,
			bpf.AttachSyscallWriteExit,
			bpf.AttachKProbeSecuritySocketSendmsgEntry,
			func() link.Link {
				return ApplyKernelVersionFunctions(t, bpf.AgentStepTIP_OUT)
			},
		},
		"GET TestIpXmit\n", Write, Read,
		FindInterestedKernEventOptions{
			findDataLenGtZeroEvent: true,
			findByDirect:           true,
			direct:                 Egress,
		}, KernDataEventAssertConditions{

			direct:           Egress,
			pid:              uint64(os.Getpid()),
			funcName:         "ip_queue_xmit",
			ignoreFuncName:   true,
			seq:              1,
			step:             bpf.AgentStepTIP_OUT,
			tsAssertFunction: func(u uint64) bool { return u > 0 },
		},
	}
	KernTestWithTcpEchoServer(options)
}

func TestDevQueueXmit(t *testing.T) {
	options := KernTestWithTcpEchoServerOptions{t, []bpf.AttachBpfProgFunction{
		bpf.AttachSyscallConnectEntry,
		bpf.AttachSyscallConnectExit,
		bpf.AttachSyscallWriteEntry,
		bpf.AttachSyscallWriteExit,
		bpf.AttachKProbeSecuritySocketSendmsgEntry,
		func() link.Link {
			return ApplyKernelVersionFunctions(t, bpf.AgentStepTIP_OUT)
		},
		func() link.Link {
			return ApplyKernelVersionFunctions(t, bpf.AgentStepTQDISC_OUT)
		},
	}, "GET DevQueueXmit\n", Write, Read,
		FindInterestedKernEventOptions{
			findDataLenGtZeroEvent: true,
			findByDirect:           true,
			direct:                 Egress,
			findByStep:             true,
			step:                   bpf.AgentStepTQDISC_OUT,
		}, KernDataEventAssertConditions{

			direct:           Egress,
			pid:              uint64(os.Getpid()),
			funcName:         "dev_queue_xmit",
			ignoreFuncName:   true,
			seq:              1,
			step:             bpf.AgentStepTQDISC_OUT,
			tsAssertFunction: func(u uint64) bool { return u > 0 },
		},
	}
	KernTestWithTcpEchoServer(options)
}

func TestDevHardStartXmit(t *testing.T) {
	options := KernTestWithTcpEchoServerOptions{
		t, []bpf.AttachBpfProgFunction{
			bpf.AttachSyscallConnectEntry,
			bpf.AttachSyscallConnectExit,
			bpf.AttachSyscallWriteEntry,
			bpf.AttachSyscallWriteExit,
			bpf.AttachKProbeSecuritySocketSendmsgEntry,
			func() link.Link {
				return ApplyKernelVersionFunctions(t, bpf.AgentStepTIP_OUT)
			},
			func() link.Link {
				return ApplyKernelVersionFunctions(t, bpf.AgentStepTDEV_OUT)
			},
		}, "GET DevHardStartXmit\n", Write, Read,
		FindInterestedKernEventOptions{
			findDataLenGtZeroEvent: true,
			findByDirect:           true,
			direct:                 Egress,
			findByStep:             true,
			step:                   bpf.AgentStepTDEV_OUT,
		}, KernDataEventAssertConditions{

			direct:           Egress,
			pid:              uint64(os.Getpid()),
			funcName:         "dev_hard_start",
			ignoreFuncName:   true,
			seq:              1,
			step:             bpf.AgentStepTDEV_OUT,
			tsAssertFunction: func(u uint64) bool { return u > 0 },
		},
	}
	KernTestWithTcpEchoServer(options)
}

func TestTracepointNetifReceiveSkb(t *testing.T) {
	curVersion := compatible.GetCurrentKernelVersion()
	delete(curVersion.Capabilities, compatible.SupportXDP)
	compatible.KernelVersionsMap.Put(curVersion.Version, curVersion)

	KernRcvTestWithHTTP(t, []bpf.AttachBpfProgFunction{
		bpf.AttachSyscallConnectEntry,
		bpf.AttachSyscallConnectExit,
		bpf.AttachSyscallRecvfromEntry,
		bpf.AttachSyscallRecvfromExit,
		bpf.AttachSyscallReadEntry,
		bpf.AttachSyscallReadExit,
		bpf.AttachSyscallWriteEntry,
		bpf.AttachSyscallWriteExit,
		bpf.AttachKProbeSecuritySocketSendmsgEntry,
		bpf.AttachKProbeSecuritySocketRecvmsgEntry,
		bpf.AttachTracepointNetifReceiveSkb,
	},
		FindInterestedKernEventOptions{
			findDataLenGtZeroEvent: true,
			findByDirect:           true,
			direct:                 Ingress,
			findByStep:             true,
			step:                   bpf.AgentStepTDEV_IN,
		}, KernDataEventAssertConditions{

			direct:            Ingress,
			pid:               uint64(os.Getpid()),
			funcName:          "netif_receive_skb",
			ignoreFuncName:    true,
			seq:               1,
			step:              bpf.AgentStepTDEV_IN,
			ignoreDataLen:     true,
			dataLenAssertFunc: func(u uint32) bool { return u > 10 },
			tsAssertFunction:  func(u uint64) bool { return u > 0 },
		})

	curVersion.Capabilities[compatible.SupportXDP] = true
	compatible.KernelVersionsMap.Put(curVersion.Version, curVersion)
	time.Sleep(1 * time.Second)
}

func TestIpRcvCore(t *testing.T) {
	KernRcvTestWithHTTP(t, []bpf.AttachBpfProgFunction{
		bpf.AttachSyscallConnectEntry,
		bpf.AttachSyscallConnectExit,
		bpf.AttachSyscallRecvfromEntry,
		bpf.AttachSyscallRecvfromExit,
		bpf.AttachSyscallReadEntry,
		bpf.AttachSyscallReadExit,
		bpf.AttachSyscallWriteEntry,
		bpf.AttachSyscallWriteExit,
		bpf.AttachKProbeSecuritySocketSendmsgEntry,
		bpf.AttachKProbeSecuritySocketRecvmsgEntry,
		func() link.Link {
			return ApplyKernelVersionFunctions(t, bpf.AgentStepTDEV_IN)
		},
		func() link.Link {
			return ApplyKernelVersionFunctions(t, bpf.AgentStepTIP_IN)
		},
	},
		FindInterestedKernEventOptions{
			findDataLenGtZeroEvent: true,
			findByDirect:           true,
			direct:                 Ingress,
			findByStep:             true,
			step:                   bpf.AgentStepTIP_IN,
		}, KernDataEventAssertConditions{

			direct:            Ingress,
			pid:               uint64(os.Getpid()),
			funcName:          "ip_rcv_core",
			ignoreFuncName:    true,
			seq:               1,
			step:              bpf.AgentStepTIP_IN,
			ignoreDataLen:     true,
			dataLenAssertFunc: func(u uint32) bool { return u > 10 },
			tsAssertFunction:  func(u uint64) bool { return u > 0 },
		})
	time.Sleep(1 * time.Second)
}

func TestTcpV4DoRcv(t *testing.T) {
	KernRcvTestWithHTTP(t, []bpf.AttachBpfProgFunction{
		bpf.AttachSyscallConnectEntry,
		bpf.AttachSyscallConnectExit,
		bpf.AttachSyscallRecvfromEntry,
		bpf.AttachSyscallRecvfromExit,
		bpf.AttachSyscallReadEntry,
		bpf.AttachSyscallReadExit,
		bpf.AttachSyscallWriteEntry,
		bpf.AttachSyscallWriteExit,
		bpf.AttachKProbeSecuritySocketSendmsgEntry,
		bpf.AttachKProbeSecuritySocketRecvmsgEntry,
		func() link.Link {
			return ApplyKernelVersionFunctions(t, bpf.AgentStepTDEV_IN)
		},
		func() link.Link {
			return ApplyKernelVersionFunctions(t, bpf.AgentStepTTCP_IN)
		},
	},
		FindInterestedKernEventOptions{
			findDataLenGtZeroEvent: true,
			findByDirect:           true,
			direct:                 Ingress,
			findByStep:             true,
			step:                   bpf.AgentStepTTCP_IN,
		}, KernDataEventAssertConditions{

			direct:            Ingress,
			pid:               uint64(os.Getpid()),
			funcName:          "tcp_v4_do_rcv",
			ignoreFuncName:    true,
			seq:               1,
			step:              bpf.AgentStepTTCP_IN,
			ignoreDataLen:     true,
			dataLenAssertFunc: func(u uint32) bool { return u > 10 },
			tsAssertFunction:  func(u uint64) bool { return u > 0 },
		})
	time.Sleep(1 * time.Second)
}

func TestSkbCopyDatagramIter(t *testing.T) {
	KernRcvTestWithHTTP(t, []bpf.AttachBpfProgFunction{
		bpf.AttachSyscallConnectEntry,
		bpf.AttachSyscallConnectExit,
		bpf.AttachSyscallRecvfromEntry,
		bpf.AttachSyscallRecvfromExit,
		bpf.AttachSyscallReadEntry,
		bpf.AttachSyscallReadExit,
		bpf.AttachSyscallWriteEntry,
		bpf.AttachSyscallWriteExit,
		bpf.AttachKProbeSecuritySocketSendmsgEntry,
		bpf.AttachKProbeSecuritySocketRecvmsgEntry,
		func() link.Link {
			return ApplyKernelVersionFunctions(t, bpf.AgentStepTDEV_IN)
		},
		func() link.Link {
			return ApplyKernelVersionFunctions(t, bpf.AgentStepTUSER_COPY)
		},
	},
		FindInterestedKernEventOptions{
			findDataLenGtZeroEvent: true,
			findByDirect:           true,
			direct:                 Ingress,
			findByStep:             true,
			step:                   bpf.AgentStepTUSER_COPY,
		}, KernDataEventAssertConditions{

			direct:            Ingress,
			pid:               uint64(os.Getpid()),
			funcName:          "skb_copy_datagr",
			ignoreFuncName:    true,
			seq:               1,
			step:              bpf.AgentStepTUSER_COPY,
			ignoreDataLen:     true,
			dataLenAssertFunc: func(u uint32) bool { return u > 10 },
			tsAssertFunction:  func(u uint64) bool { return u > 0 },
		})
	time.Sleep(1 * time.Second)
}
