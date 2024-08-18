package agent

import (
	"bytes"
	"container/list"
	"eapm-ebpf/agent/conn"
	"eapm-ebpf/agent/protocol"
	"eapm-ebpf/agent/stat"
	"eapm-ebpf/bpf"
	"eapm-ebpf/common"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jefurry/logrus"
)

var log *logrus.Logger = common.Log
var processorsNum int = 4

func SetupAgent() {
	InitReporter()

	common.LaunchEpochTime = GetMachineStartTimeNano()
	stopper := make(chan os.Signal, 1)
	connManager := conn.InitConnManager()
	statRecorder := stat.InitStatRecorder()
	pm := conn.InitProcessorManager(processorsNum, connManager)
	conn.RecordFunc = func(r protocol.Record, c *conn.Connection4) error {
		return statRecorder.ReceiveRecord(r, c)
	}
	conn.OnCloseRecordFunc = func(c *conn.Connection4) error {
		statRecorder.RemoveRecord(c.TgidFd)
		return nil
	}

	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Remove memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs bpf.AgentObjects

	spec, err := bpf.LoadAgent()
	if err != nil {
		log.Fatal("load Agent error:", err)
	}
	err = spec.RewriteConstants(map[string]interface{}{
		"agent_pid": uint32(os.Getpid()),
	})
	if err != nil {
		log.Fatal("rewrite constants error:", err)
	}

	err = spec.LoadAndAssign(&objs, nil)

	if err != nil {
		err = errors.Unwrap(errors.Unwrap(err))
		inner_err, ok := err.(*ebpf.VerifierError)
		if ok {
			inner_err.Truncated = false
			log.Errorf("loadAgentObjects: %+v", inner_err)
		} else {
			log.Errorf("loadAgentObjects: %+v", err)
		}
		return
	}

	defer objs.Close()

	links := attachBpfProgs(objs)

	for e := links.Front(); e != nil; e = e.Next() {
		if e.Value == nil {
			continue
		}
		if l, ok := e.Value.(link.Link); ok {
			defer func() {
				l.Close()
			}()
		}
	}
	// kernel >= 5.8
	syscallDataReader, err := ringbuf.NewReader(objs.AgentMaps.SyscallRb)
	if err != nil {
		log.Error("new syscall data reader ringbuffer err:", err)
		return
	}
	defer syscallDataReader.Close()

	dataReader, err := ringbuf.NewReader(objs.AgentMaps.Rb)
	if err != nil {
		log.Error("new dataReader ringbuffer err:", err)
		return
	}
	defer dataReader.Close()

	connEvtReader, err := ringbuf.NewReader(objs.AgentMaps.ConnEvtRb)
	if err != nil {
		log.Error("new connEvtReader ringbuffer err:", err)
		return
	}
	defer connEvtReader.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	stop := false
	go func() {
		<-stopper
		log.Println("stop!")
		if err := dataReader.Close(); err != nil {
			log.Fatalf("closing dataReader error: %s", err)
		}
		if err := connEvtReader.Close(); err != nil {
			log.Fatalf("closing connEvtReader error: %s", err)
		}
		if err := syscallDataReader.Close(); err != nil {
			log.Fatalf("closing syscallDataReader error: %s", err)
		}
		pm.StopAll()
		stop = true
	}()

	log.Info("Waiting for events..")

	// https://github.com/cilium/ebpf/blob/main/examples/ringbuffer/ringbuffer.c
	go func() {
		for {
			record, err := dataReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Infoln("[dataReader] Received signal, exiting..")
					return
				}
				log.Infof("[dataReader] reading from reader: %s\n", err)
				continue
			}

			if err := handleKernEvt(record.RawSample, pm); err != nil {
				log.Infof("[dataReader] handleKernEvt err: %s\n", err)
				continue
			}

		}
	}()

	go func() {
		for {
			record, err := syscallDataReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Infoln("[syscallDataReader] Received signal, exiting..")
					return
				}
				log.Infof("[syscallDataReader] reading from reader: %s\n", err)
				continue
			}
			if err := handleSyscallEvt(record.RawSample, pm); err != nil {
				log.Infof("[syscallDataReader] handleSyscallEvt err: %s\n", err)
				continue
			}
		}
	}()

	go func() {
		for {
			record, err := connEvtReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Infoln("[connEvtReader] Received signal, exiting..")
					return
				}
				log.Infof("[connEvtReader] reading from reader: %s\n", err)
				continue
			}
			if err := handleConnEvt(record.RawSample, pm); err != nil {
				log.Infof("[connEvtReader] handleKernEvt err: %s\n", err)
				continue
			}
		}
	}()

	for !stop {
		time.Sleep(time.Second * 1)
	}
	log.Println("Stopped")
	return
}

func handleConnEvt(record []byte, pm *conn.ProcessorManager) error {
	var event bpf.AgentConnEvtT
	err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event)
	if err != nil {
		return err
	}

	tgidFd := uint64(event.ConnInfo.ConnId.Upid.Pid)<<32 | uint64(event.ConnInfo.ConnId.Fd)
	p := pm.GetProcessor(int(tgidFd) % processorsNum)
	p.AddConnEvent(&event)
	return nil
}
func handleSyscallEvt(record []byte, pm *conn.ProcessorManager) error {
	// 首先看这个连接上有没有堆积的请求，如果有继续堆积
	// 如果没有作为新的请求
	event := new(bpf.SyscallEventData)
	err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event.SyscallEvent)
	if err != nil {
		return err
	}
	msgSize := event.SyscallEvent.BufSize
	buf := make([]byte, msgSize)
	headerSize := uint(unsafe.Sizeof(event.SyscallEvent)) - 4
	err = binary.Read(bytes.NewBuffer(record[headerSize:]), binary.LittleEndian, &buf)
	event.Buf = buf

	tgidFd := event.SyscallEvent.Ke.ConnIdS.TgidFd
	p := pm.GetProcessor(int(tgidFd) % processorsNum)
	p.AddSyscallEvent(event)
	return nil
}
func handleKernEvt(record []byte, pm *conn.ProcessorManager) error {
	var event bpf.AgentKernEvt
	err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event)
	if err != nil {
		return err
	}
	tgidFd := event.ConnIdS.TgidFd
	p := pm.GetProcessor(int(tgidFd) % processorsNum)
	p.AddKernEvent(&event)
	return nil
}

func attachBpfProgs(objs bpf.AgentObjects) *list.List {
	linkList := list.New()

	l := kprobe("__sys_accept4", objs.AgentPrograms.Accept4Entry)
	linkList.PushBack(l)
	l = kretprobe("__sys_accept4", objs.AgentPrograms.SysAccept4Ret)
	linkList.PushBack(l)

	l = kretprobe("sock_alloc", objs.AgentPrograms.SockAllocRet)
	linkList.PushBack(l)

	l = kretprobe("__sys_connect", objs.AgentPrograms.SysConnectRet)
	linkList.PushBack(l)
	l = kprobe("__sys_connect", objs.AgentPrograms.ConnectEntry)
	linkList.PushBack(l)

	l = kprobe("__x64_sys_close", objs.AgentPrograms.CloseEntry)
	linkList.PushBack(l)
	l = kretprobe("__x64_sys_close", objs.AgentPrograms.SysCloseRet)
	linkList.PushBack(l)

	l = kprobe("__x64_sys_write", objs.AgentPrograms.WriteEnter)
	linkList.PushBack(l)
	l = kretprobe("__x64_sys_write", objs.AgentPrograms.WriteReturn)
	linkList.PushBack(l)

	l = kprobe("do_writev", objs.AgentPrograms.WritevEnter)
	linkList.PushBack(l)
	l = kretprobe("do_writev", objs.AgentPrograms.WritevReturn)
	linkList.PushBack(l)

	l = kprobe("__sys_sendto", objs.AgentPrograms.SendtoEnter)
	linkList.PushBack(l)
	l = kretprobe("__sys_sendto", objs.AgentPrograms.SendtoReturn)
	linkList.PushBack(l)

	l = kprobe("__x64_sys_read", objs.AgentPrograms.ReadEnter)
	linkList.PushBack(l)
	l = kretprobe("__x64_sys_read", objs.AgentPrograms.ReadReturn)
	linkList.PushBack(l)

	l = kprobe("do_readv", objs.AgentPrograms.ReadvEnter)
	linkList.PushBack(l)
	l = kretprobe("do_readv", objs.AgentPrograms.ReadvReturn)
	linkList.PushBack(l)

	l = kprobe("__sys_recvfrom", objs.AgentPrograms.RecvfromEnter)
	linkList.PushBack(l)
	l = kretprobe("__sys_recvfrom", objs.AgentPrograms.RecvfromReturn)
	linkList.PushBack(l)

	l = kprobe("security_socket_recvmsg", objs.AgentPrograms.SecuritySocketRecvmsgEnter)
	linkList.PushBack(l)
	l = kprobe("security_socket_sendmsg", objs.AgentPrograms.SecuritySocketSendmsgEnter)
	linkList.PushBack(l)

	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "tcp_destroy_sock",
		Program: objs.AgentPrograms.TcpDestroySock,
	})
	if err != nil {
		log.Fatal("tcp_destroy_sock failed: ", err)
	}
	linkList.PushBack(l)

	l = kprobe("ip_queue_xmit", objs.AgentPrograms.IpQueueXmit)
	linkList.PushBack(l)
	l = kprobe("dev_queue_xmit", objs.AgentPrograms.DevQueueXmit)
	linkList.PushBack(l)
	l = kprobe("dev_hard_start_xmit", objs.AgentPrograms.DevHardStartXmit)
	linkList.PushBack(l)

	if l, err = kprobe2("ip_rcv_core", objs.AgentPrograms.IpRcvCore); err != nil {
		l = kprobe("ip_rcv_core.isra.0", objs.AgentPrograms.IpRcvCore)
	}
	linkList.PushBack(l)

	l = kprobe("tcp_v4_do_rcv", objs.AgentPrograms.TcpV4DoRcv)
	linkList.PushBack(l)
	l = kprobe("__skb_datagram_iter", objs.AgentPrograms.SkbCopyDatagramIter)
	linkList.PushBack(l)

	ifname := "eth0" // TODO
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	l, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.AgentPrograms.XdpProxy,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	linkList.PushBack(l)
	return linkList
}

func kprobe(func_name string, prog *ebpf.Program) link.Link {
	if link, err := link.Kprobe(func_name, prog, nil); err != nil {
		log.Fatalf("kprobe failed: %s, %s", func_name, err)
		return nil
	} else {
		return link
	}
}

func kprobe2(func_name string, prog *ebpf.Program) (link.Link, error) {
	if link, err := link.Kprobe(func_name, prog, nil); err != nil {
		log.Fatalf("kprobe2 failed: %s, %s", func_name, err)
		return nil, err
	} else {
		return link, nil
	}
}

func kretprobe(func_name string, prog *ebpf.Program) link.Link {
	if link, err := link.Kretprobe(func_name, prog, nil); err != nil {
		log.Fatalf("kretprobe failed: %s, %s", func_name, err)
		return nil
	} else {
		return link
	}
}
