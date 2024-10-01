package bpf

type SyscallEvent struct {
	Ke      AgentKernEvt
	BufSize uint32
}

type SyscallEventData struct {
	SyscallEvent SyscallEvent
	Buf          []byte
}
type SslEventHeader struct {
	Ke         AgentKernEvt
	SyscallSeq uint64
	SyscallLen uint32
	BufSize    uint32
}

type SslData struct {
	SslEventHeader SslEventHeader
	Buf            []byte
}

func IsEgressStep(step AgentStepT) bool {
	return step <= AgentStepTNIC_OUT
}

func IsIngressStep(step AgentStepT) bool {
	return step >= AgentStepTNIC_IN
}
