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
	return TracepointNoError("syscalls", "sys_enter_accept4", GetProgram(programs, "TracepointSyscallsSysEnterAccept4"))
}

func AttachSyscallAcceptExit(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_exit_accept4", GetProgram(programs, "TracepointSyscallsSysExitAccept4"))
}

/* sock_alloc */
func AttachSyscallSockAllocExit(programs interface{}) link.Link {
	return KretprobeNoError("sock_alloc", GetProgram(programs, "SockAllocRet"))
}

/* connect pair */
func AttachSyscallConnectEntry(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_enter_connect", GetProgram(programs, "TracepointSyscallsSysEnterConnect"))
}

func AttachSyscallConnectExit(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_exit_connect", GetProgram(programs, "TracepointSyscallsSysExitConnect"))
}

/* close pair */
func AttachSyscallCloseEntry(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_enter_close", GetProgram(programs, "TracepointSyscallsSysEnterClose"))
}

func AttachSyscallCloseExit(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_exit_close", GetProgram(programs, "TracepointSyscallsSysExitClose"))
}

/* write pair */
func AttachSyscallWriteEntry(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_enter_write", GetProgram(programs, "TracepointSyscallsSysEnterWrite"))
}

func AttachSyscallWriteExit(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_exit_write", GetProgram(programs, "TracepointSyscallsSysExitWrite"))
}

/* sendmsg pair */
func AttachSyscallSendMsgEntry(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_enter_sendmsg", GetProgram(programs, "TracepointSyscallsSysEnterSendmsg"))
}

func AttachSyscallSendMsgExit(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_exit_sendmsg", GetProgram(programs, "TracepointSyscallsSysExitSendmsg"))
}

/* recvmsg pair */
func AttachSyscallRecvMsgEntry(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_enter_recvmsg", GetProgram(programs, "TracepointSyscallsSysEnterRecvmsg"))
}

func AttachSyscallRecvMsgExit(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_exit_recvmsg", GetProgram(programs, "TracepointSyscallsSysExitRecvmsg"))
}

/* writev pair */
func AttachSyscallWritevEntry(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_enter_writev", GetProgram(programs, "TracepointSyscallsSysEnterWritev"))
}

func AttachSyscallWritevExit(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_exit_writev", GetProgram(programs, "TracepointSyscallsSysExitWritev"))
}

/* sendto pair */
func AttachSyscallSendtoEntry(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_enter_sendto", GetProgram(programs, "TracepointSyscallsSysEnterSendto"))
}

func AttachSyscallSendtoExit(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_exit_sendto", GetProgram(programs, "TracepointSyscallsSysExitSendto"))
}

/* read pair */
func AttachSyscallReadEntry(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_enter_read", GetProgram(programs, "TracepointSyscallsSysEnterRead"))
}

func AttachSyscallReadExit(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_exit_read", GetProgram(programs, "TracepointSyscallsSysExitRead"))
}

/* readv pair */
func AttachSyscallReadvEntry(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_enter_readv", GetProgram(programs, "TracepointSyscallsSysEnterReadv"))
}

func AttachSyscallReadvExit(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_exit_readv", GetProgram(programs, "TracepointSyscallsSysExitReadv"))
}

/* recvfrom pair */
func AttachSyscallRecvfromEntry(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_enter_recvfrom", GetProgram(programs, "TracepointSyscallsSysEnterRecvfrom"))
}

func AttachSyscallRecvfromExit(programs interface{}) link.Link {
	return TracepointNoError("syscalls", "sys_exit_recvfrom", GetProgram(programs, "TracepointSyscallsSysExitRecvfrom"))
}

/* security_socket_recvmsg */
func AttachKProbeSecuritySocketRecvmsgEntry(programs interface{}) link.Link {
	return Kprobe2("security_socket_recvmsg", GetProgram(programs, "SecuritySocketRecvmsgEnter"))
}

/* security_socket_sendmsg */
func AttachKProbeSecuritySocketSendmsgEntry(programs interface{}) link.Link {
	return Kprobe2("security_socket_sendmsg", GetProgram(programs, "SecuritySocketSendmsgEnter"))
}

/* tcp_destroy_sock */
func AttachRawTracepointTcpDestroySockEntry(programs interface{}) (link.Link, error) {
	return link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "tcp_destroy_sock",
		Program: GetProgram(programs, "TcpDestroySock"),
	})
	// if err != nil {
	// 	log.Fatal("tcp_destroy_sock failed: ", err)
	// }
	// return l
}

func AttachKProbeDevQueueXmitEntry(programs interface{}) (link.Link, error) {
	return Kprobe("dev_queue_xmit", GetProgram(programs, "DevQueueXmit"))
}
func AttachKProbeDevHardStartXmitEntry(programs interface{}) (link.Link, error) {
	return Kprobe("dev_hard_start_xmit", GetProgram(programs, "DevHardStartXmit"))
}
func AttachKProbeTcpV4DoRcvEntry(programs interface{}) (link.Link, error) {
	return Kprobe("tcp_v4_do_rcv", GetProgram(programs, "TcpV4DoRcv"))
}

func AttachTracepointNetifReceiveSkb(programs interface{}) link.Link {
	return TracepointNoError("net", "netif_receive_skb", GetProgram(programs, "TracepointNetifReceiveSkb"))
}
func AttachXdpWithSpecifiedIfName(programs interface{}, ifname string) (link.Link, error) {

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		// log.Fatalf("Getting interface %s: %s", ifname, err)
		return nil, err
	}

	return link.AttachXDP(link.XDPOptions{
		Program:   GetProgram(programs, "XdpProxy"),
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
}
func AttachXdp(programs interface{}) (link.Link, error) {
	return AttachXdpWithSpecifiedIfName(programs, "eth0")
}

func Kprobe(func_name string, prog *ebpf.Program) (link.Link, error) {
	return link.Kprobe(func_name, prog, nil)
}

func Kretprobe(func_name string, prog *ebpf.Program) (link.Link, error) {
	return link.Kretprobe(func_name, prog, nil)
}

func Tracepoint(group string, name string, prog *ebpf.Program) (link.Link, error) {
	return link.Tracepoint(group, name, prog, nil)
}
func TracepointNoError(group string, name string, prog *ebpf.Program) link.Link {
	l, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		log.Fatalf("failed to attach tracepoint, group: %s name: %s, err: %v", group, name, err)
		return nil
	} else {
		return l
	}
}

func KretprobeNoError(func_name string, prog *ebpf.Program) link.Link {
	l, err := link.Kretprobe(func_name, prog, nil)
	if err != nil {
		log.Fatalf("failed to attach kretprobe, func_name: %s , err: %v", func_name, err)
		return nil
	} else {
		return l
	}
}

func Kprobe2(func_name string, prog *ebpf.Program) link.Link {
	if link, err := link.Kprobe(func_name, prog, nil); err != nil {
		log.Fatalf("kprobe2 failed: %s, %s, fallbacking..", func_name, err)
		return nil
	} else {
		return link
	}
}
