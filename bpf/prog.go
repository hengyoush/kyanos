package bpf

import (
	"log"
	"net"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var Objs any

type AttachBpfProgFunction func(interface{}) link.Link

func GetProgram(programs any, fieldName string) *ebpf.Program {
	oldprograms, isOld := programs.(AgentOldPrograms)
	if isOld {
		v := reflect.ValueOf(oldprograms)
		f := v.FieldByName(fieldName).Interface()
		return f.(*ebpf.Program)
	} else {
		newprograms := programs.(AgentPrograms)
		v := reflect.ValueOf(newprograms)
		f := v.FieldByName(fieldName).Interface()
		return f.(*ebpf.Program)
	}
}

/* accept pair */
func AttachSyscallAcceptEntry(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_enter_accept4", GetProgram(programs, "TracepointSyscallsSysEnterAccept4"))
}

func AttachSyscallAcceptExit(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_accept4", GetProgram(programs, "TracepointSyscallsSysExitAccept4"))
}

/* sock_alloc */
func AttachSyscallSockAllocExit(programs interface{}) link.Link {
	return kretprobe("sock_alloc", GetProgram(programs, "SockAllocRet"))
}

/* connect pair */
func AttachSyscallConnectEntry(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_enter_connect", GetProgram(programs, "TracepointSyscallsSysEnterConnect"))
}

func AttachSyscallConnectExit(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_connect", GetProgram(programs, "TracepointSyscallsSysExitConnect"))
}

/* close pair */
func AttachSyscallCloseEntry(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_enter_close", GetProgram(programs, "TracepointSyscallsSysEnterClose"))
}

func AttachSyscallCloseExit(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_close", GetProgram(programs, "TracepointSyscallsSysExitClose"))
}

/* write pair */
func AttachSyscallWriteEntry(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_enter_write", GetProgram(programs, "TracepointSyscallsSysEnterWrite"))
}

func AttachSyscallWriteExit(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_write", GetProgram(programs, "TracepointSyscallsSysExitWrite"))
}

/* sendmsg pair */
func AttachSyscallSendMsgEntry(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_enter_sendmsg", GetProgram(programs, "TracepointSyscallsSysEnterSendmsg"))
}

func AttachSyscallSendMsgExit(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_sendmsg", GetProgram(programs, "TracepointSyscallsSysExitSendmsg"))
}

/* recvmsg pair */
func AttachSyscallRecvMsgEntry(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_enter_recvmsg", GetProgram(programs, "TracepointSyscallsSysEnterRecvmsg"))
}

func AttachSyscallRecvMsgExit(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_recvmsg", GetProgram(programs, "TracepointSyscallsSysExitRecvmsg"))
}

/* writev pair */
func AttachSyscallWritevEntry(programs interface{}) link.Link {
	return kprobe("do_writev", GetProgram(programs, "WritevEnter"))
}

func AttachSyscallWritevExit(programs interface{}) link.Link {
	return kretprobe("do_writev", GetProgram(programs, "WritevReturn"))
}

/* sendto pair */
func AttachSyscallSendtoEntry(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_enter_sendto", GetProgram(programs, "TracepointSyscallsSysEnterSendto"))
}

func AttachSyscallSendtoExit(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_sendto", GetProgram(programs, "TracepointSyscallsSysExitSendto"))
}

/* read pair */
func AttachSyscallReadEntry(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_enter_read", GetProgram(programs, "TracepointSyscallsSysEnterRead"))
}

func AttachSyscallReadExit(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_read", GetProgram(programs, "TracepointSyscallsSysExitRead"))
}

/* readv pair */
func AttachSyscallReadvEntry(programs interface{}) link.Link {
	return kprobe("do_readv", GetProgram(programs, "ReadvEnter"))
}

func AttachSyscallReadvExit(programs interface{}) link.Link {
	return kretprobe("do_readv", GetProgram(programs, "ReadvReturn"))
}

/* recvfrom pair */
func AttachSyscallRecvfromEntry(programs interface{}) link.Link {
	return kprobe("__sys_recvfrom", GetProgram(programs, "RecvfromEnter"))
}

func AttachSyscallRecvfromExit(programs interface{}) link.Link {
	return tracepoint("syscalls", "sys_exit_recvfrom", GetProgram(programs, "TracepointSyscallsSysExitRecvfrom"))
}

/* security_socket_recvmsg */
func AttachKProbeSecuritySocketRecvmsgEntry(programs interface{}) link.Link {
	return kprobe("security_socket_recvmsg", GetProgram(programs, "SecuritySocketRecvmsgEnter"))
}

/* security_socket_sendmsg */
func AttachKProbeSecuritySocketSendmsgEntry(programs interface{}) link.Link {
	return kprobe("security_socket_sendmsg", GetProgram(programs, "SecuritySocketSendmsgEnter"))
}

/* tcp_destroy_sock */
func AttachRawTracepointTcpDestroySockEntry(programs interface{}) link.Link {
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "tcp_destroy_sock",
		Program: GetProgram(programs, "TcpDestroySock"),
	})
	if err != nil {
		log.Fatal("tcp_destroy_sock failed: ", err)
	}
	return l
}

func AttachKProbeIpQueueXmitEntry(programs interface{}) link.Link {
	return kprobe("__ip_queue_xmit", GetProgram(programs, "IpQueueXmit"))
}
func AttachKProbeDevQueueXmitEntry(programs interface{}) link.Link {
	return kprobe("dev_queue_xmit", GetProgram(programs, "DevQueueXmit"))
}
func AttachKProbeDevHardStartXmitEntry(programs interface{}) link.Link {
	return kprobe("dev_hard_start_xmit", GetProgram(programs, "DevHardStartXmit"))
}
func AttachKProbIpRcvCoreEntry(programs interface{}) link.Link {
	l, err := kprobe2("ip_rcv_core", GetProgram(programs, "IpRcvCore"))
	if err != nil {
		l = kprobe("ip_rcv_core.isra.0", GetProgram(programs, "IpRcvCore"))
	}
	return l
}
func AttachKProbeTcpV4DoRcvEntry(programs interface{}) link.Link {
	return kprobe("tcp_v4_do_rcv", GetProgram(programs, "TcpV4DoRcv"))
}

func AttachTracepointNetifReceiveSkb(programs interface{}) link.Link {
	return tracepoint("net", "netif_receive_skb", GetProgram(programs, "TracepointNetifReceiveSkb"))
}
func AttachKProbeSkbCopyDatagramIterEntry(programs interface{}) link.Link {
	return kprobe("__skb_datagram_iter", GetProgram(programs, "SkbCopyDatagramIter"))
}
func AttachXdpWithSpecifiedIfName(programs interface{}, ifname string) link.Link {

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   GetProgram(programs, "XdpProxy"),
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	return l
}
func AttachXdp(programs interface{}) link.Link {
	return AttachXdpWithSpecifiedIfName(programs, "eth0")
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
		log.Printf("kprobe2 failed: %s, %s, fallbacking..", func_name, err)
		return nil, err
	} else {
		return link, nil
	}
}
