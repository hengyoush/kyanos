package compatible

import (
	"cmp"
	"fmt"
	"kyanos/bpf"
	"kyanos/common"
	"slices"
	"strings"

	"github.com/emirpasic/gods/maps/treemap"
)

var log = common.DefaultLog

type Capability int

const (
	SupportXDP Capability = iota
	SupportConstants
	SupportRawTracepoint
	SupportRingBuffer
	SupportBTF
	SupportFilterByContainer
)

type InstrumentFunction struct {
	KernelFunctionName string
	BPFGoProgName      string
}

func (f *InstrumentFunction) GetRealKernelFunctionName() string {
	idx := strings.LastIndex(f.KernelFunctionName, "/")
	if idx != -1 {
		return f.KernelFunctionName[idx+1:]
	} else {
		return f.KernelFunctionName
	}
}

func (f *InstrumentFunction) IsKprobe() bool {
	return strings.HasPrefix(f.KernelFunctionName, "kprobe")
}
func (f *InstrumentFunction) IsKRetprobe() bool {
	return strings.HasPrefix(f.KernelFunctionName, "kretprobe")
}
func (f *InstrumentFunction) IsTracepoint() bool {
	return strings.HasPrefix(f.KernelFunctionName, "tracepoint")
}
func (f *InstrumentFunction) GetKprobeName() string {
	return f.GetRealKernelFunctionName()
}
func (f *InstrumentFunction) GetKRetprobeName() string {
	return f.GetRealKernelFunctionName()
}
func (f *InstrumentFunction) GetTracepointGroupName() string {
	firstIdx := strings.Index(f.KernelFunctionName, "/")
	secondIdx := strings.LastIndex(f.KernelFunctionName, "/")
	return f.KernelFunctionName[firstIdx+1 : secondIdx]
}

func (f *InstrumentFunction) GetTracepointName() string {
	secondIdx := strings.LastIndex(f.KernelFunctionName, "/")
	return f.KernelFunctionName[secondIdx+1:]
}

type KernelVersion struct {
	Version             string
	InstrumentFunctions map[bpf.AgentStepT][]InstrumentFunction
	Capabilities        map[Capability]bool
}

func (v KernelVersion) SupportCapability(c Capability) bool {
	return v.Capabilities[c]
}

var KernelVersionsMap *treemap.Map

func GetCurrentKernelVersion() KernelVersion {
	version := common.GetKernelVersion()
	v := GetBestMatchedKernelVersion(version.Core().String())
	return v
}

func GetBestMatchedKernelVersion(version string) KernelVersion {
	foundKey, foundValue := KernelVersionsMap.Floor(version)
	if foundKey == nil {
		foundKey, foundValue := KernelVersionsMap.Ceiling(version)
		if foundKey != nil {
			log.Debugf("Can't find version: %s, use the smallest version current supported: %s", version, foundKey)
			return foundValue.(KernelVersion)
		} else {
			log.Fatalln(fmt.Sprintf("kernel version: %s is too old, currently not suppport", version))
			return KernelVersion{}
		}
	} else {
		return foundValue.(KernelVersion)
	}
}

func init() {
	KernelVersionsMap = treemap.NewWith(func(a, b interface{}) int {
		return cmp.Compare(a.(string), b.(string))
	})

	baseVersion := KernelVersion{
		Version: "5.15.0",
		InstrumentFunctions: map[bpf.AgentStepT][]InstrumentFunction{
			bpf.AgentStepTIP_OUT:    {InstrumentFunction{"kprobe/__ip_queue_xmit", "IpQueueXmit"}},
			bpf.AgentStepTQDISC_OUT: {InstrumentFunction{"kprobe/dev_queue_xmit", "DevQueueXmit"}},
			bpf.AgentStepTDEV_OUT:   {InstrumentFunction{"kprobe/dev_hard_start_xmit", "DevHardStartXmit"}},
			bpf.AgentStepTDEV_IN:    {InstrumentFunction{"tracepoint/net/netif_receive_skb", "TracepointNetifReceiveSkb"}},
			bpf.AgentStepTIP_IN:     {InstrumentFunction{"kprobe/ip_rcv_core", "IpRcvCore"}},
			bpf.AgentStepTTCP_IN:    {InstrumentFunction{"kprobe/tcp_v4_do_rcv", "TcpV4DoRcv"}},
			bpf.AgentStepTUSER_COPY: {InstrumentFunction{"kprobe/__skb_datagram_iter", "SkbCopyDatagramIter"}},
		},
		Capabilities: map[Capability]bool{
			SupportConstants:         true,
			SupportRawTracepoint:     true,
			SupportRingBuffer:        false,
			SupportBTF:               true,
			SupportFilterByContainer: true,
		},
	}
	baseVersion.addBackupInstrumentFunction(bpf.AgentStepTQDISC_OUT, InstrumentFunction{"kprobe/__dev_queue_xmit", "DevQueueXmit"})
	v5d15 := copyKernelVersion(baseVersion)
	KernelVersionsMap.Put(v5d15.Version, v5d15)

	v5d4 := copyKernelVersion(v5d15)
	v5d4.Version = "5.4.0"
	v5d4.addBackupInstrumentFunction(bpf.AgentStepTIP_IN, InstrumentFunction{"kprobe/ip_rcv_core.isra.0", "IpRcvCore"})
	v5d4.addBackupInstrumentFunction(bpf.AgentStepTIP_IN, InstrumentFunction{"kprobe/ip_rcv_core.isra.20", "IpRcvCore"})
	v5d4.removeCapability(SupportRingBuffer).removeCapability(SupportXDP)
	KernelVersionsMap.Put(v5d4.Version, v5d4)

	v4d14 := copyKernelVersion(v5d4)
	v4d14.Version = "4.14.0"
	v4d14.InstrumentFunctions[bpf.AgentStepTIP_OUT] =
		[]InstrumentFunction{{"kprobe/ip_queue_xmit", "IpQueueXmit"}}
	v4d14.addBackupInstrumentFunction(bpf.AgentStepTIP_OUT, InstrumentFunction{"kprobe/__ip_queue_xmit", "IpQueueXmit"})
	v4d14.InstrumentFunctions[bpf.AgentStepTIP_IN] =
		[]InstrumentFunction{{"kprobe/ip_rcv", "IpRcvCore"}}
	v4d14.InstrumentFunctions[bpf.AgentStepTUSER_COPY] =
		[]InstrumentFunction{{"kprobe/skb_copy_datagram_iter", "SkbCopyDatagramIter"}}
	v4d14.removeCapability(SupportConstants).removeCapability(SupportRawTracepoint).removeCapability(SupportBTF).removeCapability(SupportXDP)
	KernelVersionsMap.Put(v4d14.Version, v4d14)

	v310 := copyKernelVersion(v5d4)
	v310.Version = "3.10.0"
	v310.InstrumentFunctions[bpf.AgentStepTIP_OUT] =
		[]InstrumentFunction{{"kprobe/ip_queue_xmit", "IpQueueXmit2"}}
	v310.InstrumentFunctions[bpf.AgentStepTUSER_COPY] =
		[]InstrumentFunction{{"kprobe/skb_copy_datagram_iovec", "SkbCopyDatagramIter"}}
	v310.addBackupInstrumentFunction(bpf.AgentStepTIP_IN, InstrumentFunction{"kprobe/ip_rcv", "IpRcvCore"})
	v310.removeCapability(SupportConstants).
		removeCapability(SupportRawTracepoint).
		removeCapability(SupportXDP).
		removeCapability(SupportBTF).
		removeCapability(SupportFilterByContainer)
	KernelVersionsMap.Put(v310.Version, v310)
}

func (i *KernelVersion) addBackupInstrumentFunction(step bpf.AgentStepT, function InstrumentFunction) {
	i.InstrumentFunctions[step] = append(i.InstrumentFunctions[step], function)
}

func (i *KernelVersion) removeCapability(cap Capability) *KernelVersion {
	delete(i.Capabilities, cap)
	return i
}

func copyKernelVersion(this KernelVersion) KernelVersion {
	result := KernelVersion{
		Version: this.Version,
	}
	result.Capabilities = make(map[Capability]bool)
	for key, value := range this.Capabilities {
		result.Capabilities[key] = value
	}

	result.InstrumentFunctions = make(map[bpf.AgentStepT][]InstrumentFunction)
	for key, value := range this.InstrumentFunctions {
		result.InstrumentFunctions[key] = slices.Clone(value)
	}
	return result
}
