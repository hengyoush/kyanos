package main

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var LaunchEpochTime uint64

func main() {
	LaunchEpochTime = GetMachineStartTimeNano()
	stopper := make(chan os.Signal, 1)
	connManager := InitConnManager()

	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Remove memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs pktlatencyObjects
	if err := loadPktlatencyObjects(&objs, nil); err != nil {
		log.Println("loadPktlatencyObjects:", err)
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
	dataReader, err := ringbuf.NewReader(objs.pktlatencyMaps.Rb)
	if err != nil {
		log.Println("new dataReader ringbuffer err:", err)
		return
	}
	defer dataReader.Close()

	connEvtReader, err := ringbuf.NewReader(objs.pktlatencyMaps.ConnEvtRb)
	if err != nil {
		log.Println("new connEvtReader ringbuffer err:", err)
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
		stop = true
	}()

	log.Println("Waiting for events..")

	// https://github.com/cilium/ebpf/blob/main/examples/ringbuffer/ringbuffer.c
	go func() {
		for {
			record, err := dataReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("[dataReader] Received signal, exiting..")
					return
				}
				log.Printf("[dataReader] reading from reader: %s", err)
				continue
			}
			if err := handleKernEvt(record.RawSample, connManager); err != nil {
				log.Printf("[dataReader] handleKernEvt err: %s", err)
				continue
			}

		}
	}()

	go func() {
		for {
			record, err := connEvtReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("[connEvtReader] Received signal, exiting..")
					return
				}
				log.Printf("[connEvtReader] reading from reader: %s", err)
				continue
			}
			if err := handleConnEvt(record.RawSample, connManager); err != nil {
				log.Printf("[connEvtReader] handleKernEvt err: %s", err)
				continue
			}
		}
	}()

	// time.Sleep(time.Second * 5)
	// runtime.GC()
	// log.Println("Gced")

	for !stop {
		time.Sleep(time.Second * 1)
	}
	log.Println("Stopped")
	return
}
func handleConnEvt(record []byte, connManager *ConnManager) error {
	var event pktlatencyConnEvtT
	err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event)
	if err != nil {
		return err
	}
	TgidFd := uint64(event.ConnInfo.ConnId.Upid.Pid)<<32 | uint64(event.ConnInfo.ConnId.Fd)
	conn := Connection4{
		localIp:    event.ConnInfo.Laddr.In4.SinAddr.S_addr,
		remoteIp:   event.ConnInfo.Raddr.In4.SinAddr.S_addr,
		localPort:  event.ConnInfo.Laddr.In4.SinPort,
		remotePort: event.ConnInfo.Raddr.In4.SinPort,
		protocol:   event.ConnInfo.Protocol,
		role:       event.ConnInfo.Role,
		tgidFd:     uint64(event.ConnInfo.ConnId.Upid.Pid)<<32 | uint64(event.ConnInfo.ConnId.Fd),
	}

	if event.ConnType == pktlatencyConnTypeTKConnect {
		connManager.AddConnection4(TgidFd, &conn)
	} else if event.ConnType == pktlatencyConnTypeTKClose {
		go func() {
			time.Sleep(1 * time.Second)
			connManager.RemoveConnection4(TgidFd)
		}()
	} else if event.ConnType == pktlatencyConnTypeTKProtocolInfer {
		// 协议推断
		conn := connManager.findConnection4(TgidFd)
		if conn != nil {
			conn.protocol = event.ConnInfo.Protocol
		} else {
			return nil
		}
		if conn.protocol != pktlatencyTrafficProtocolTKProtocolUnknown {
			ReportDataEvents(conn.TempEvents, conn)
		}
		// 清空, 这里可能有race
		conn.TempEvents = conn.TempEvents[0:0]
	}
	direct := "=>"
	if event.ConnInfo.Role != pktlatencyEndpointRoleTKRoleClient {
		direct = "<="
	}
	eventType := "connect"
	if event.ConnType == pktlatencyConnTypeTKClose {
		eventType = "close"
	} else if event.ConnType == pktlatencyConnTypeTKProtocolInfer {
		eventType = "infer"
	}
	event.Ts += LaunchEpochTime
	log.Printf("[conn][tgid=%d fd=%d] %s:%d %s %s:%d | type: %s, protocol: %d, \n", event.ConnInfo.ConnId.Upid.Pid, event.ConnInfo.ConnId.Fd, intToIP(conn.localIp), conn.localPort, direct, intToIP(conn.remoteIp), conn.remotePort, eventType, conn.protocol)
	go func() {
		// ReportConnEvent(&event)
	}()
	return nil
}
func handleKernEvt(record []byte, connManager *ConnManager) error {
	var event pktlatencyKernEvt
	err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event)
	if err != nil {
		return err
	}
	tgidFd := event.ConnIdS.TgidFd
	conn := connManager.findConnection4(tgidFd)
	event.Ts += LaunchEpochTime
	if conn != nil {
		direct := "=>"
		if event.ConnIdS.Direct == pktlatencyTrafficDirectionTKIngress {
			direct = "<="
		}
		log.Printf("[data][tgid_fd=%d][func=%s][%s] %s:%d %s %s:%d | %d:%d\n", tgidFd, int8ToStr(event.FuncName[:]), StepAsString(Step(event.Step)), intToIP(conn.localIp), conn.localPort, direct, intToIP(conn.remoteIp), conn.remotePort, event.Seq, event.Len)

	} else {
		log.Println("failed to retrieve conn from connManager")
	}
	if event.Len > 0 && conn != nil && conn.protocol != pktlatencyTrafficProtocolTKProtocolUnknown {
		go func() {
			if conn != nil {
				if conn.protocol == pktlatencyTrafficProtocolTKProtocolUnset {
					conn.AddEvent(&event)
				} else if conn.protocol != pktlatencyTrafficProtocolTKProtocolUnknown {
					// ReportDataEvent(&event, conn)
				}
			}
		}()
	}
	return nil
}

func attachBpfProgs(objs pktlatencyObjects) *list.List {
	linkList := list.New()

	l := kprobe("__sys_accept4", objs.pktlatencyPrograms.Accept4Entry)
	linkList.PushBack(l)
	l = kretprobe("__sys_accept4", objs.pktlatencyPrograms.SysAccept4Ret)
	linkList.PushBack(l)

	l = kretprobe("sock_alloc", objs.pktlatencyPrograms.SockAllocRet)
	linkList.PushBack(l)

	l = kretprobe("__sys_connect", objs.pktlatencyPrograms.SysConnectRet)
	linkList.PushBack(l)
	l = kprobe("__sys_connect", objs.pktlatencyPrograms.ConnectEntry)
	linkList.PushBack(l)

	l = kprobe("__x64_sys_close", objs.pktlatencyPrograms.CloseEntry)
	linkList.PushBack(l)
	l = kretprobe("__x64_sys_close", objs.pktlatencyPrograms.SysCloseRet)
	linkList.PushBack(l)

	l = kprobe("__x64_sys_write", objs.pktlatencyPrograms.WriteEnter)
	linkList.PushBack(l)
	l = kretprobe("__x64_sys_write", objs.pktlatencyPrograms.WriteReturn)
	linkList.PushBack(l)

	l = kprobe("__sys_sendto", objs.pktlatencyPrograms.SendtoEnter)
	linkList.PushBack(l)
	l = kretprobe("__sys_sendto", objs.pktlatencyPrograms.SendtoReturn)
	linkList.PushBack(l)

	l = kprobe("__x64_sys_read", objs.pktlatencyPrograms.ReadEnter)
	linkList.PushBack(l)
	l = kretprobe("__x64_sys_read", objs.pktlatencyPrograms.ReadReturn)
	linkList.PushBack(l)

	l = kprobe("__sys_recvfrom", objs.pktlatencyPrograms.RecvfromEnter)
	linkList.PushBack(l)
	l = kretprobe("__sys_recvfrom", objs.pktlatencyPrograms.RecvfromReturn)
	linkList.PushBack(l)

	l = kprobe("security_socket_recvmsg", objs.pktlatencyPrograms.SecuritySocketRecvmsgEnter)
	linkList.PushBack(l)
	l = kprobe("security_socket_sendmsg", objs.pktlatencyPrograms.SecuritySocketSendmsgEnter)
	linkList.PushBack(l)

	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "tcp_destroy_sock",
		Program: objs.pktlatencyPrograms.TcpDestroySock,
	})
	if err != nil {
		log.Fatal("tcp_destroy_sock failed: ", err)
	}
	linkList.PushBack(l)

	l = kprobe("ip_queue_xmit", objs.pktlatencyPrograms.IpQueueXmit)
	linkList.PushBack(l)
	l = kprobe("dev_queue_xmit", objs.pktlatencyPrograms.DevQueueXmit)
	linkList.PushBack(l)
	l = kprobe("dev_hard_start_xmit", objs.pktlatencyPrograms.DevHardStartXmit)
	linkList.PushBack(l)

	if l, err = kprobe2("ip_rcv_core", objs.pktlatencyPrograms.IpRcvCore); err != nil {
		l = kprobe("ip_rcv_core.isra.0", objs.pktlatencyPrograms.IpRcvCore)
	}
	linkList.PushBack(l)

	l = kprobe("tcp_v4_do_rcv", objs.pktlatencyPrograms.TcpV4DoRcv)
	linkList.PushBack(l)
	l = kprobe("__skb_datagram_iter", objs.pktlatencyPrograms.SkbCopyDatagramIter)
	linkList.PushBack(l)

	ifname := "eth0" // TODO
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	l, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.pktlatencyPrograms.XdpProxy,
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
