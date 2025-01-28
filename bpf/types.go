package bpf

type SyscallEvent struct {
	Ke      AgentKernEvt
	BufSize uint32
}

func (s SyscallEvent) GetSourceFunction() AgentSourceFunctionT {
	return AgentSourceFunctionT(s.Ke.FuncName[0])
}

func (s SyscallEvent) GetStartTs() uint64 {
	return s.Ke.Ts
}

func (s SyscallEvent) GetEndTs() uint64 {
	return s.Ke.Ts + uint64(s.Ke.TsDelta)
}

type SyscallEventData struct {
	SyscallEvent SyscallEvent
	Buf          []byte
}
type SslEventHeader struct {
	Ke         AgentKernEvt
	SyscallSeq uint32
	SyscallLen uint32
	BufSize    uint32
}

func (s SslEventHeader) GetStartTs() uint64 {
	return s.Ke.Ts
}

func (s SslEventHeader) GetEndTs() uint64 {
	return s.Ke.Ts + uint64(s.Ke.TsDelta)
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
