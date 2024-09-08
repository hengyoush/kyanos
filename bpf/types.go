package bpf

type SyscallEvent struct {
	Ke      AgentKernEvt
	BufSize uint32
}

type SyscallEventData struct {
	SyscallEvent SyscallEvent
	Buf          []byte
}

func IsEgressStep(step AgentStepT) bool {
	return step <= AgentStepTNIC_OUT
}

func IsIngressStep(step AgentStepT) bool {
	return step >= AgentStepTNIC_IN
}
