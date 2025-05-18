package bpf

import (
	"kyanos/common"
	"net"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var Objs any

type AttachBpfProgFunction func() (link.Link, error)

func GetProgramFromObjs(objs any, progName string) *ebpf.Program {
	val := reflect.ValueOf(objs)

	programField := val.Elem().Field(0)
	if !programField.IsValid() {
		return nil
	}
	programSpecsVal := programField
	fieldName := progName
	fieldVal := programSpecsVal.FieldByName(fieldName)
	if fieldVal.IsValid() && fieldVal.Kind() == reflect.Ptr && !fieldVal.IsNil() {
		program := fieldVal.Interface().(*ebpf.Program)
		return program
	} else {
		return nil
	}
}

/* accept pair */
func AttachSyscallAcceptEntry() (link.Link, error) {
	return FentryOrTracepoint("__sys_accept4", GetProgramFromObjs(Objs, "FentrySysAccept4"),
		"syscalls", "sys_enter_accept4",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterAccept4"))
}

func AttachSyscallAcceptExit() (link.Link, error) {
	return FexitOrTracepoint("__sys_accept4", GetProgramFromObjs(Objs, "FexitSysAccept4"),
		"syscalls", "sys_exit_accept4",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitAccept4"))
}

/* sock_alloc */
func AttachSyscallSockAllocExit() (link.Link, error) {
	return Kretprobe("sock_alloc", GetProgramFromObjs(Objs, "SockAllocRet"))
}

/* connect pair */
func AttachSyscallConnectEntry() (link.Link, error) {
	return FentryOrTracepoint("__sys_connect", GetProgramFromObjs(Objs, "FentrySysConnect"),
		"syscalls", "sys_enter_connect",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterConnect"))

}

func AttachSyscallConnectExit() (link.Link, error) {
	return FexitOrTracepoint("__sys_connect", GetProgramFromObjs(Objs, "FexitSysConnect"),
		"syscalls", "sys_exit_connect",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitConnect"))
}

/* close pair */
func AttachSyscallCloseEntry() (link.Link, error) {
	return FentryOrTracepoint("__x64_sys_close", GetProgramFromObjs(Objs, "FentrySysClose"),
		"syscalls", "sys_enter_close",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterClose"))
}

func AttachSyscallCloseExit() (link.Link, error) {
	return FexitOrTracepoint("__x64_sys_close", GetProgramFromObjs(Objs, "FexitSysClose"),
		"syscalls", "sys_exit_close",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitClose"))
}

/* write pair */
func AttachSyscallWriteEntry() (link.Link, error) {
	return FentryOrTracepoint("__x64_sys_write", GetProgramFromObjs(Objs, "FentrySysWrite"),
		"syscalls", "sys_enter_write",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterWrite"))
}

func AttachSyscallWriteExit() (link.Link, error) {
	return FexitOrTracepoint("__x64_sys_write", GetProgramFromObjs(Objs, "FexitSysWrite"),
		"syscalls", "sys_exit_write",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitWrite"))
}

/* sendmsg pair */
func AttachSyscallSendMsgEntry() (link.Link, error) {
	return FentryOrTracepoint("__sys_sendmsg", GetProgramFromObjs(Objs, "FentrySysSendmsg"),
		"syscalls", "sys_enter_sendmsg",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterSendmsg"))
}

func AttachSyscallSendMsgExit() (link.Link, error) {
	return FexitOrTracepoint("__x64_sys_sendmsg", GetProgramFromObjs(Objs, "FexitSysSendmsg"),
		"syscalls", "sys_exit_sendmsg",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitSendmsg"))
}

/* sendmmsg pair */
func AttachSyscallSendMMsgEntry() (link.Link, error) {
	return FentryOrTracepoint("__sys_sendmmsg", GetProgramFromObjs(Objs, "FentrySysSendmmsg"),
		"syscalls", "sys_enter_sendmmsg",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterSendmmsg"))
}

func AttachSyscallSendMMsgExit() (link.Link, error) {
	return FexitOrTracepoint("__x64_sys_sendmmsg", GetProgramFromObjs(Objs, "FexitSysSendmmsg"),
		"syscalls", "sys_exit_sendmmsg",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitSendmmsg"))
}

/* recvmmsg pair */
func AttachSyscallRecvMMsgEntry() (link.Link, error) {
	return FentryOrTracepoint("__x64_sys_recvmmsg", GetProgramFromObjs(Objs, "FentrySysRecvmmsg"),
		"syscalls", "sys_enter_recvmmsg",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterRecvmmsg"))
}

func AttachSyscallRecvMMsgExit() (link.Link, error) {
	return FexitOrTracepoint("__x64_sys_recvmmsg", GetProgramFromObjs(Objs, "FexitSysRecvmmsg"),
		"syscalls", "sys_exit_recvmmsg",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitRecvmmsg"))
}

/* sendfile pair */
func AttachSyscallSendFile64Entry() (link.Link, error) {
	return FentryOrTracepoint("__x64_sys_sendfile64", GetProgramFromObjs(Objs, "FentrySysSendfile64"),
		"syscalls", "sys_enter_sendfile64",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterSendfile64"))
}

func AttachSyscallSendFile64Exit() (link.Link, error) {
	return FexitOrTracepoint("__x64_sys_sendfile64", GetProgramFromObjs(Objs, "FexitSysSendfile64"),
		"syscalls", "sys_exit_sendfile64",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitSendfile64"))
}

/* recvmsg pair */
func AttachSyscallRecvMsgEntry() (link.Link, error) {
	return FentryOrTracepoint("__x64_sys_recvmsg", GetProgramFromObjs(Objs, "FentrySysRecvmsg"),
		"syscalls", "sys_enter_recvmsg",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterRecvmsg"))
}

func AttachSyscallRecvMsgExit() (link.Link, error) {
	return FexitOrTracepoint("__x64_sys_recvmsg", GetProgramFromObjs(Objs, "FexitSysRecvmsg"),
		"syscalls", "sys_exit_recvmsg",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitRecvmsg"))
}

/* writev pair */
func AttachSyscallWritevEntry() (link.Link, error) {
	return FentryOrTracepoint("__x64_sys_writev", GetProgramFromObjs(Objs, "FentrySysWritev"),
		"syscalls", "sys_enter_writev",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterWritev"))
}

func AttachSyscallWritevExit() (link.Link, error) {
	return FexitOrTracepoint("__x64_sys_writev", GetProgramFromObjs(Objs, "FexitSysWritev"),
		"syscalls", "sys_exit_writev",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitWritev"))
}

/* sendto pair */
func AttachSyscallSendtoEntry() (link.Link, error) {
	return FentryOrTracepoint("__sys_sendto", GetProgramFromObjs(Objs, "FentrySysSendto"),
		"syscalls", "sys_enter_sendto",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterSendto"))
}

func AttachSyscallSendtoExit() (link.Link, error) {
	return FexitOrTracepoint("__x64_sys_sendto", GetProgramFromObjs(Objs, "FexitSysSendto"),
		"syscalls", "sys_exit_sendto",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitSendto"))
}

/* read pair */
func AttachSyscallReadEntry() (link.Link, error) {
	return FentryOrTracepoint("__x64_sys_read", GetProgramFromObjs(Objs, "FentrySysRead"),
		"syscalls", "sys_enter_read",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterRead"))
}

func AttachSyscallReadExit() (link.Link, error) {
	return FexitOrTracepoint("__x64_sys_read", GetProgramFromObjs(Objs, "FexitSysRead"),
		"syscalls", "sys_exit_read",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitRead"))
}

/* readv pair */
func AttachSyscallReadvEntry() (link.Link, error) {
	return FentryOrTracepoint("__x64_sys_readv", GetProgramFromObjs(Objs, "FentrySysReadv"),
		"syscalls", "sys_enter_readv",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterReadv"))
}

func AttachSyscallReadvExit() (link.Link, error) {
	return FexitOrTracepoint("__x64_sys_readv", GetProgramFromObjs(Objs, "FexitSysReadv"),
		"syscalls", "sys_exit_readv",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitReadv"))
}

/* recvfrom pair */
func AttachSyscallRecvfromEntry() (link.Link, error) {
	return FentryOrTracepoint("__x64_sys_recvfrom", GetProgramFromObjs(Objs, "FentrySysRecvfrom"),
		"syscalls", "sys_enter_recvfrom",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysEnterRecvfrom"))
}

func AttachSyscallRecvfromExit() (link.Link, error) {
	return FexitOrTracepoint("__x64_sys_recvfrom", GetProgramFromObjs(Objs, "FexitSysRecvfrom"),
		"syscalls", "sys_exit_recvfrom",
		GetProgramFromObjs(Objs, "TracepointSyscallsSysExitRecvfrom"))
}

func AttachSchedProcessExec() (link.Link, error) {
	return Tracepoint("sched", "sched_process_exec", GetProgramFromObjs(Objs, "TracepointSchedSchedProcessExec"))
}

func AttachSchedProcessExit() (link.Link, error) {
	return Tracepoint("sched", "sched_process_exit", GetProgramFromObjs(Objs, "TracepointSchedSchedProcessExit"))
}

func AttachNfNatManipPkt() (link.Link, error) {
	return Kprobe("nf_nat_manip_pkt", GetProgramFromObjs(Objs, "KprobeNfNatManipPkt"))
}

func AttachNfNatPacket() (link.Link, error) {
	return Kprobe("nf_nat_packet", GetProgramFromObjs(Objs, "KprobeNfNatPacket"))
}

/* security_socket_recvmsg */
func AttachKProbeSecuritySocketRecvmsgEntry() (link.Link, error) {
	return FentryOrKprobe("security_socket_recvmsg", GetProgramFromObjs(Objs, "FentrySecuritySocketRecvmsg"),
		GetProgramFromObjs(Objs, "SecuritySocketRecvmsgRet"))
	// return Kprobe("security_socket_recvmsg", GetProgramFromObjs(Objs, "SecuritySocketRecvmsgEnter"))
}

/* security_socket_sendmsg */
func AttachKProbeSecuritySocketSendmsgEntry() (link.Link, error) {
	return FentryOrKprobe("security_socket_sendmsg", GetProgramFromObjs(Objs, "FentrySecuritySocketSendmsg"),
		GetProgramFromObjs(Objs, "SecuritySocketSendmsgRet"))
	// return Kprobe("security_socket_sendmsg", GetProgramFromObjs(Objs, "SecuritySocketSendmsgEnter"))
}

/* tcp_destroy_sock */
func AttachRawTracepointTcpDestroySockEntry() (link.Link, error) {
	return link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "tcp_destroy_sock",
		Program: GetProgramFromObjs(Objs, "TcpDestroySock"),
	})
	// if err != nil {
	// 	log.Fatal("tcp_destroy_sock failed: ", err)
	// }
	// return l
}

func AttachKProbeDevQueueXmitEntry() (link.Link, error) {
	return Kprobe("dev_queue_xmit", GetProgramFromObjs(Objs, "DevQueueXmit"))
}
func AttachKProbeDevHardStartXmitEntry() (link.Link, error) {
	return Kprobe("dev_hard_start_xmit", GetProgramFromObjs(Objs, "DevHardStartXmit"))
}
func AttachKProbeTcpV4DoRcvEntry() (link.Link, error) {
	return Kprobe("tcp_v4_do_rcv", GetProgramFromObjs(Objs, "TcpV4DoRcv"))
}

func AttachTracepointNetifReceiveSkb() (link.Link, error) {
	return Tracepoint("net", "netif_receive_skb", GetProgramFromObjs(Objs, "TracepointNetifReceiveSkb"))
}
func AttachXdpWithSpecifiedIfName(ifname string) (link.Link, error) {

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		// log.Fatalf("Getting interface %s: %s", ifname, err)
		return nil, err
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   GetProgramFromObjs(Objs, "XdpProxy"),
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   GetProgramFromObjs(Objs, "XdpProxy"),
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
	}
	return l, err
}
func AttachXdp() (link.Link, error) {
	return AttachXdpWithSpecifiedIfName("eth0")
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
		common.BPFLog.Warnf("failed to attach tracepoint, group: %s name: %s, err: %v", group, name, err)
		return nil
	} else {
		return l
	}
}

func Fentry(funcName string, prog *ebpf.Program) (link.Link, error) {
	return link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
}

func Fexit(funcName string, prog *ebpf.Program) (link.Link, error) {
	return link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFExit,
	})
}

func FentryOrTracepoint(func_name string, fentryProg *ebpf.Program, group string, name string, tracepointProg *ebpf.Program) (link.Link, error) {
	l, err := Fentry(func_name, fentryProg)
	if err != nil {
		l, err = Tracepoint(group, name, tracepointProg)
		if err != nil {
			common.BPFLog.Errorf("failed to attach fentry or tracepoint, group: %s name: %s, err: %v", group, name, err)
		}
	} else {
		common.BPFLog.Debugf("attached fentry to %s", func_name)
	}
	if l != nil {
		common.BPFLog.Debugf("attached fentry to %s", func_name)
		return l, nil
	} else {
		common.BPFLog.Errorf("failed to attach fentry to %s", func_name)
		return nil, err
	}
}

func FentryOrKprobe(func_name string, fentryProg *ebpf.Program, kprobeProg *ebpf.Program) (link.Link, error) {
	l, err := Fentry(func_name, fentryProg)
	if err != nil {
		l, err = Kprobe(func_name, kprobeProg)
		if err != nil {
			common.BPFLog.Errorf("failed to attach fentry or kprobe, func_name: %s, err: %v", func_name, err)
		}
	} else {
		common.BPFLog.Debugf("attached fentry to %s", func_name)
	}
	if l != nil {
		common.BPFLog.Debugf("attached fentry to %s", func_name)
		return l, nil
	} else {
		common.BPFLog.Errorf("failed to attach fentry to %s", func_name)
		return nil, err
	}
}

func FexitOrTracepoint(func_name string, fexitProg *ebpf.Program, group string, name string, tracepointProg *ebpf.Program) (link.Link, error) {
	l, err := Fexit(func_name, fexitProg)
	if err != nil {
		l, err = Tracepoint(group, name, tracepointProg)
		if err != nil {
			common.BPFLog.Errorf("failed to attach fexit or tracepoint, group: %s name: %s, err: %v", group, name, err)
		}
	} else {
		common.BPFLog.Debugf("attached fexit to %s", func_name)
	}
	if l != nil {
		common.BPFLog.Debugf("attached fexit to %s", func_name)
		return l, nil
	} else {
		common.BPFLog.Errorf("failed to attach fexit to %s", func_name)
		return nil, err
	}
}

func FexitOrKretprobe(func_name string, fexitProg *ebpf.Program, kretprobeProg *ebpf.Program) (link.Link, error) {
	l, err := Fexit(func_name, fexitProg)
	if err != nil {
		l, err = Kretprobe(func_name, kretprobeProg)
		if err != nil {
			common.BPFLog.Errorf("failed to attach fexit or kretprobe, func_name: %s, err: %v", func_name, err)
		}
	} else {
		common.BPFLog.Debugf("attached fexit to %s", func_name)
	}
	if l != nil {
		common.BPFLog.Debugf("attached fexit to %s", func_name)
		return l, nil
	} else {
		common.BPFLog.Errorf("failed to attach fexit to %s", func_name)
		return nil, err
	}
}
