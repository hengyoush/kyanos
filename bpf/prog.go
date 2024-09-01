package bpf

import (
	"log"
	"net"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type AttachBpfProgFunction func(interface{}) link.Link

func GetProgram(objs any, fieldName string) *ebpf.Program {
	oldObjs, isOld := objs.(AgentOldPrograms)
	if isOld {
		v := reflect.ValueOf(oldObjs)
		f := v.FieldByName(fieldName).Interface()
		return f.(*ebpf.Program)
	} else {
		newObjs := objs.(AgentPrograms)
		v := reflect.ValueOf(newObjs)
		f := v.FieldByName(fieldName).Interface()
		return f.(*ebpf.Program)
	}
}

/* accept pair */
func AttachSyscallAcceptEntry(objs interface{}) link.Link {
	return kprobe("__sys_accept4", GetProgram(objs, "Accept4Entry"))
}

func AttachSyscallAcceptExit(objs interface{}) link.Link {
	return kretprobe("__sys_accept4", GetProgram(objs, "SysAccept4Ret"))
}

/* sock_alloc */
func AttachSyscallSockAllocExit(objs interface{}) link.Link {
	return kretprobe("sock_alloc", GetProgram(objs, "SockAllocRet"))
}

/* connect pair */
func AttachSyscallConnectEntry(objs interface{}) link.Link {
	return kprobe("__sys_connect", GetProgram(objs, "ConnectEntry"))
}

func AttachSyscallConnectExit(objs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_connect", GetProgram(objs, "TracepointSyscallsSysExitConnect"))
}

/* close pair */
func AttachSyscallCloseEntry(objs interface{}) link.Link {
	return kprobe("sys_close", GetProgram(objs, "CloseEntry"))
}

func AttachSyscallCloseExit(objs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_close", GetProgram(objs, "TracepointSyscallsSysExitClose"))
}

/* write pair */
func AttachSyscallWriteEntry(objs interface{}) link.Link {
	return kprobe("sys_write", GetProgram(objs, "WriteEnter"))
}

func AttachSyscallWriteExit(objs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_write", GetProgram(objs, "TracepointSyscallsSysExitWrite"))
}

/* sendmsg pair */
func AttachSyscallSendMsgEntry(objs interface{}) link.Link {
	return kprobe("sys_sendmsg", GetProgram(objs, "SendmsgEnter"))
}

func AttachSyscallSendMsgExit(objs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_sendmsg", GetProgram(objs, "TracepointSyscallsSysExitSendmsg"))
}

/* recvmsg pair */
func AttachSyscallRecvMsgEntry(objs interface{}) link.Link {
	return kprobe("sys_recvmsg", GetProgram(objs, "RecvmsgEnter"))
}

func AttachSyscallRecvMsgExit(objs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_recvmsg", GetProgram(objs, "TracepointSyscallsSysExitRecvmsg"))
}

/* writev pair */
func AttachSyscallWritevEntry(objs interface{}) link.Link {
	return kprobe("do_writev", GetProgram(objs, "WritevEnter"))
}

func AttachSyscallWritevExit(objs interface{}) link.Link {
	return kretprobe("do_writev", GetProgram(objs, "WritevReturn"))
}

/* sendto pair */
func AttachSyscallSendtoEntry(objs interface{}) link.Link {
	return tracepoint("syscalls", "sys_enter_sendto", GetProgram(objs, "TracepointSyscallsSysEnterSendto"))
}

func AttachSyscallSendtoExit(objs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_sendto", GetProgram(objs, "TracepointSyscallsSysExitSendto"))
}

/* read pair */
func AttachSyscallReadEntry(objs interface{}) link.Link {
	return kprobe("sys_read", GetProgram(objs, "ReadEnter"))
}

func AttachSyscallReadExit(objs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_read", GetProgram(objs, "TracepointSyscallsSysExitRead"))
}

/* readv pair */
func AttachSyscallReadvEntry(objs interface{}) link.Link {
	return kprobe("do_readv", GetProgram(objs, "ReadvEnter"))
}

func AttachSyscallReadvExit(objs interface{}) link.Link {
	return kretprobe("do_readv", GetProgram(objs, "ReadvReturn"))
}

/* recvfrom pair */
func AttachSyscallRecvfromEntry(objs interface{}) link.Link {
	return kprobe("__sys_recvfrom", GetProgram(objs, "RecvfromEnter"))
}

func AttachSyscallRecvfromExit(objs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_recvfrom", GetProgram(objs, "TracepointSyscallsSysExitRecvfrom"))
}

/* security_socket_recvmsg */
func AttachKProbeSecuritySocketRecvmsgEntry(objs interface{}) link.Link {
	return kprobe("security_socket_recvmsg", GetProgram(objs, "SecuritySocketRecvmsgEnter"))
}

/* security_socket_sendmsg */
func AttachKProbeSecuritySocketSendmsgEntry(objs interface{}) link.Link {
	return kprobe("security_socket_sendmsg", GetProgram(objs, "SecuritySocketSendmsgEnter"))
}

/* tcp_destroy_sock */
func AttachRawTracepointTcpDestroySockEntry(objs interface{}) link.Link {
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "tcp_destroy_sock",
		Program: GetProgram(objs, "TcpDestroySock"),
	})
	if err != nil {
		log.Fatal("tcp_destroy_sock failed: ", err)
	}
	return l
}

func AttachKProbeIpQueueXmitEntry(objs interface{}) link.Link {
	return kprobe("ip_queue_xmit", GetProgram(objs, "IpQueueXmit"))
}
func AttachKProbeDevQueueXmitEntry(objs interface{}) link.Link {
	return kprobe("dev_queue_xmit", GetProgram(objs, "DevQueueXmit"))
}
func AttachKProbeDevHardStartXmitEntry(objs interface{}) link.Link {
	return kprobe("dev_hard_start_xmit", GetProgram(objs, "DevHardStartXmit"))
}
func AttachKProbIpRcvCoreEntry(objs interface{}) link.Link {
	l, err := kprobe2("ip_rcv_core", GetProgram(objs, "IpRcvCore"))
	if err != nil {
		l = kprobe("ip_rcv_core.isra.0", GetProgram(objs, "IpRcvCore"))
	}
	return l
}
func AttachKProbeTcpV4DoRcvEntry(objs interface{}) link.Link {
	return kprobe("tcp_v4_do_rcv", GetProgram(objs, "TcpV4DoRcv"))
}
func AttachKProbeSkbCopyDatagramIterEntry(objs interface{}) link.Link {
	return kprobe("__skb_datagram_iter", GetProgram(objs, "SkbCopyDatagramIter"))
}

func AttachXdp(objs interface{}) link.Link {
	ifname := "eth0"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   GetProgram(objs, "XdpProxy"),
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
