package bpf

type SyscallEvent struct {
	Ke      AgentKernEvt
	BufSize uint32
}

type SyscallEventData struct {
	SyscallEvent SyscallEvent
	Buf          []byte
}
