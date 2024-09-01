package bpf

import (
	"log"
	"net"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type AttachBpfProgFunction func(interface{}) link.Link

func GetProgram(maps any, fieldName string) *ebpf.Program {
	oldmaps, isOld := maps.(AgentOldPrograms)
	if isOld {
		v := reflect.ValueOf(oldmaps)
		f := v.FieldByName(fieldName).Interface()
		return f.(*ebpf.Program)
	} else {
		newmaps := maps.(AgentPrograms)
		v := reflect.ValueOf(newmaps)
		f := v.FieldByName(fieldName).Interface()
		return f.(*ebpf.Program)
	}
}

/* accept pair */
func AttachSyscallAcceptEntry(maps interface{}) link.Link {
	return kprobe("__sys_accept4", GetProgram(maps, "Accept4Entry"))
}

func AttachSyscallAcceptExit(maps interface{}) link.Link {
	return kretprobe("__sys_accept4", GetProgram(maps, "SysAccept4Ret"))
}

/* sock_alloc */
func AttachSyscallSockAllocExit(maps interface{}) link.Link {
	return kretprobe("sock_alloc", GetProgram(maps, "SockAllocRet"))
}

/* connect pair */
func AttachSyscallConnectEntry(maps interface{}) link.Link {
	return kprobe("__sys_connect", GetProgram(maps, "ConnectEntry"))
}

func AttachSyscallConnectExit(maps interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_connect", GetProgram(maps, "TracepointSyscallsSysExitConnect"))
}

/* close pair */
func AttachSyscallCloseEntry(maps interface{}) link.Link {
	return kprobe("sys_close", GetProgram(maps, "CloseEntry"))
}

func AttachSyscallCloseExit(maps interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_close", GetProgram(maps, "TracepointSyscallsSysExitClose"))
}

/* write pair */
func AttachSyscallWriteEntry(maps interface{}) link.Link {
	return kprobe("sys_write", GetProgram(maps, "WriteEnter"))
}

func AttachSyscallWriteExit(maps interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_write", GetProgram(maps, "TracepointSyscallsSysExitWrite"))
}

/* sendmsg pair */
func AttachSyscallSendMsgEntry(maps interface{}) link.Link {
	return kprobe("sys_sendmsg", GetProgram(maps, "SendmsgEnter"))
}

func AttachSyscallSendMsgExit(maps interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_sendmsg", GetProgram(maps, "TracepointSyscallsSysExitSendmsg"))
}

/* recvmsg pair */
func AttachSyscallRecvMsgEntry(maps interface{}) link.Link {
	return kprobe("sys_recvmsg", GetProgram(maps, "RecvmsgEnter"))
}

func AttachSyscallRecvMsgExit(maps interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_recvmsg", GetProgram(maps, "TracepointSyscallsSysExitRecvmsg"))
}

/* writev pair */
func AttachSyscallWritevEntry(maps interface{}) link.Link {
	return kprobe("do_writev", GetProgram(maps, "WritevEnter"))
}

func AttachSyscallWritevExit(maps interface{}) link.Link {
	return kretprobe("do_writev", GetProgram(maps, "WritevReturn"))
}

/* sendto pair */
func AttachSyscallSendtoEntry(maps interface{}) link.Link {
	return tracepoint("syscalls", "sys_enter_sendto", GetProgram(maps, "TracepointSyscallsSysEnterSendto"))
}

func AttachSyscallSendtoExit(maps interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_sendto", GetProgram(maps, "TracepointSyscallsSysExitSendto"))
}

/* read pair */
func AttachSyscallReadEntry(maps interface{}) link.Link {
	return kprobe("sys_read", GetProgram(maps, "ReadEnter"))
}

func AttachSyscallReadExit(maps interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_read", GetProgram(maps, "TracepointSyscallsSysExitRead"))
}

/* readv pair */
func AttachSyscallReadvEntry(maps interface{}) link.Link {
	return kprobe("do_readv", GetProgram(maps, "ReadvEnter"))
}

func AttachSyscallReadvExit(maps interface{}) link.Link {
	return kretprobe("do_readv", GetProgram(maps, "ReadvReturn"))
}

/* recvfrom pair */
func AttachSyscallRecvfromEntry(maps interface{}) link.Link {
	return kprobe("__sys_recvfrom", GetProgram(maps, "RecvfromEnter"))
}

func AttachSyscallRecvfromExit(maps interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_recvfrom", GetProgram(maps, "TracepointSyscallsSysExitRecvfrom"))
}

/* security_socket_recvmsg */
func AttachKProbeSecuritySocketRecvmsgEntry(maps interface{}) link.Link {
	return kprobe("security_socket_recvmsg", GetProgram(maps, "SecuritySocketRecvmsgEnter"))
}

/* security_socket_sendmsg */
func AttachKProbeSecuritySocketSendmsgEntry(maps interface{}) link.Link {
	return kprobe("security_socket_sendmsg", GetProgram(maps, "SecuritySocketSendmsgEnter"))
}

/* tcp_destroy_sock */
func AttachRawTracepointTcpDestroySockEntry(maps interface{}) link.Link {
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "tcp_destroy_sock",
		Program: GetProgram(maps, "TcpDestroySock"),
	})
	if err != nil {
		log.Fatal("tcp_destroy_sock failed: ", err)
	}
	return l
}

func AttachKProbeIpQueueXmitEntry(maps interface{}) link.Link {
	return kprobe("ip_queue_xmit", GetProgram(maps, "IpQueueXmit"))
}
func AttachKProbeDevQueueXmitEntry(maps interface{}) link.Link {
	return kprobe("dev_queue_xmit", GetProgram(maps, "DevQueueXmit"))
}
func AttachKProbeDevHardStartXmitEntry(maps interface{}) link.Link {
	return kprobe("dev_hard_start_xmit", GetProgram(maps, "DevHardStartXmit"))
}
func AttachKProbIpRcvCoreEntry(maps interface{}) link.Link {
	l, err := kprobe2("ip_rcv_core", GetProgram(maps, "IpRcvCore"))
	if err != nil {
		l = kprobe("ip_rcv_core.isra.0", GetProgram(maps, "IpRcvCore"))
	}
	return l
}
func AttachKProbeTcpV4DoRcvEntry(maps interface{}) link.Link {
	return kprobe("tcp_v4_do_rcv", GetProgram(maps, "TcpV4DoRcv"))
}
func AttachKProbeSkbCopyDatagramIterEntry(maps interface{}) link.Link {
	return kprobe("__skb_datagram_iter", GetProgram(maps, "SkbCopyDatagramIter"))
}

func AttachXdp(maps interface{}) link.Link {
	ifname := "eth0"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   GetProgram(maps, "XdpProxy"),
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	return l
}

func kprobe(func_name string, prog *ebpf.Program) link.Link {
	if link, err := link.Kprobe(func_name, prog, nil); err != nil {
		log.Fatalf("kprobe failed: %s, %s", func_name, err)
		return nil
	} else {
		return link
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

func tracepoint(group string, name string, prog *ebpf.Program) link.Link {
	if link, err := link.Tracepoint(group, name, prog, nil); err != nil {
		log.Fatalf("tp failed: %s, %s", group+":"+name, err)
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
