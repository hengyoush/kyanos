package bpf

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

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

/* accept pair */
func AttachSyscallAcceptEntry(objs AgentObjects) link.Link {
	return kprobe("__sys_accept4", objs.AgentPrograms.Accept4Entry)
}

func AttachSyscallAcceptExit(objs AgentObjects) link.Link {
	return kretprobe("__sys_accept4", objs.AgentPrograms.SysAccept4Ret)
}

/* sock_alloc */
func AttachSyscallSockAllocExit(objs AgentObjects) link.Link {
	return kretprobe("sock_alloc", objs.AgentPrograms.SockAllocRet)
}

/* connect pair */
func AttachSyscallConnectEntry(objs AgentObjects) link.Link {
	return kprobe("__sys_connect", objs.AgentPrograms.ConnectEntry)
}

func AttachSyscallConnectExit(objs AgentObjects) link.Link {
	return tracepoint("syscalls", "sys_exit_connect", objs.AgentPrograms.TracepointSyscallsSysExitConnect)
}

/* close pair */
func AttachSyscallCloseEntry(objs AgentObjects) link.Link {
	return kprobe("sys_close", objs.AgentPrograms.CloseEntry)
}

func AttachSyscallCloseExit(objs AgentObjects) link.Link {
	return tracepoint("syscalls", "sys_exit_close", objs.AgentPrograms.TracepointSyscallsSysExitClose)
}

/* write pair */
func AttachSyscallWriteEntry(objs AgentObjects) link.Link {
	return kprobe("sys_write", objs.AgentPrograms.WriteEnter)
}

func AttachSyscallWriteExit(objs AgentObjects) link.Link {
	return tracepoint("syscalls", "sys_exit_write", objs.AgentPrograms.TracepointSyscallsSysExitWrite)
}

/* sendmsg pair */
func AttachSyscallSendMsgEntry(objs AgentObjects) link.Link {
	return kprobe("sys_sendmsg", objs.AgentPrograms.SendmsgEnter)
}

func AttachSyscallSendMsgExit(objs AgentObjects) link.Link {
	return tracepoint("syscalls", "sys_exit_sendmsg", objs.AgentPrograms.TracepointSyscallsSysExitSendmsg)
}

/* recvmsg pair */
func AttachSyscallRecvMsgEntry(objs AgentObjects) link.Link {
	return kprobe("sys_recvmsg", objs.AgentPrograms.RecvfromEnter)
}

func AttachSyscallRecvMsgExit(objs AgentObjects) link.Link {
	return tracepoint("syscalls", "sys_exit_recvmsg", objs.AgentPrograms.TracepointSyscallsSysExitRecvmsg)
}

/* writev pair */
func AttachSyscallWritevEntry(objs AgentObjects) link.Link {
	return kprobe("do_writev", objs.AgentPrograms.WritevEnter)
}

func AttachSyscallWritevExit(objs AgentObjects) link.Link {
	return kretprobe("do_writev", objs.AgentPrograms.WritevReturn)
}

/* sendto pair */
func AttachSyscallSendtoEntry(objs AgentObjects) link.Link {
	return tracepoint("syscalls", "sys_enter_sendto", objs.AgentPrograms.TracepointSyscallsSysEnterSendto)
}

func AttachSyscallSendtoExit(objs AgentObjects) link.Link {
	return tracepoint("syscalls", "sys_exit_sendto", objs.AgentPrograms.TracepointSyscallsSysExitSendto)
}

/* read pair */
func AttachSyscallReadEntry(objs AgentObjects) link.Link {
	return kprobe("sys_read", objs.AgentPrograms.ReadEnter)
}

func AttachSyscallReadExit(objs AgentObjects) link.Link {
	return tracepoint("syscalls", "sys_exit_read", objs.AgentPrograms.TracepointSyscallsSysExitRead)
}

/* readv pair */
func AttachSyscallReadvEntry(objs AgentObjects) link.Link {
	return kprobe("do_readv", objs.AgentPrograms.ReadvEnter)
}

func AttachSyscallReadvExit(objs AgentObjects) link.Link {
	return kretprobe("do_readv", objs.AgentPrograms.ReadvReturn)
}

/* recvfrom pair */
func AttachSyscallRecvfromEntry(objs AgentObjects) link.Link {
	return kprobe("__sys_recvfrom", objs.AgentPrograms.RecvfromEnter)
}

func AttachSyscallRecvfromExit(objs AgentObjects) link.Link {
	return tracepoint("syscalls", "sys_exit_recvfrom", objs.AgentPrograms.TracepointSyscallsSysExitRecvfrom)
}

/* security_socket_recvmsg */
func AttachKProbeSecuritySocketRecvmsgEntry(objs AgentObjects) link.Link {
	return kprobe("security_socket_recvmsg", objs.AgentPrograms.SecuritySocketRecvmsgEnter)
}

/* security_socket_sendmsg */
func AttachKProbeSecuritySocketSendmsgEntry(objs AgentObjects) link.Link {
	return kprobe("security_socket_sendmsg", objs.AgentPrograms.SecuritySocketSendmsgEnter)
}

/* tcp_destroy_sock */
func AttachRawTracepointTcpDestroySockEntry(objs AgentObjects) link.Link {
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "tcp_destroy_sock",
		Program: objs.AgentPrograms.TcpDestroySock,
	})
	if err != nil {
		log.Fatal("tcp_destroy_sock failed: ", err)
	}
	return l
}
