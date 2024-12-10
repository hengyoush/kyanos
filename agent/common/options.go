package common

import (
	"container/list"
	"context"
	"fmt"
	anc "kyanos/agent/analysis/common"
	"kyanos/agent/compatible"
	"kyanos/agent/conn"
	"kyanos/agent/metadata"
	"kyanos/agent/protocol"
	"kyanos/agent/render/watch"
	"kyanos/bpf"
	"kyanos/common"
	"os"
	"runtime"
	"strings"
)

type LoadBpfProgramFunction func() *list.List
type InitCompletedHook func()
type ConnManagerInitHook func(*conn.ConnManager)

const perfEventDataBufferSize = 30 * 1024 * 1024
const perfEventControlBufferSize = 1 * 1024 * 1024

type AgentOptions struct {
	Stopper                chan os.Signal
	CustomSyscallEventHook bpf.SyscallEventHook
	CustomConnEventHook    bpf.ConnEventHook
	CustomKernEventHook    bpf.KernEventHook
	CustomSslEventHook     bpf.SslEventHook
	InitCompletedHook      InitCompletedHook
	ConnManagerInitHook    ConnManagerInitHook
	LoadBpfProgramFunction LoadBpfProgramFunction
	ProcessorsNum          int
	MessageFilter          protocol.ProtocolFilter
	LatencyFilter          protocol.LatencyFilter
	TraceSide              common.SideEnum
	IfName                 string
	BTFFilePath            string
	protocol.SizeFilter
	AnalysisEnable bool
	anc.AnalysisOptions
	PerfEventBufferSizeForData  int
	PerfEventBufferSizeForEvent int
	DisableOpensslUprobe        bool
	WatchOptions                watch.WatchOptions
	PerformanceMode             bool

	FilterComm              string
	ProcessExecEventChannel chan *bpf.AgentProcessExecEvent
	DockerEndpoint          string
	ContainerdEndpoint      string
	CriRuntimeEndpoint      string
	ContainerId             string
	ContainerName           string
	PodName                 string
	PodNameSpace            string

	Cc                  *metadata.ContainerCache
	Objs                any
	Ctx                 context.Context
	Kv                  *compatible.KernelVersion
	LoadPorgressChannel chan string
}

func (o AgentOptions) FilterByContainer() bool {
	return o.ContainerId != "" || o.ContainerName != "" || o.PodName != ""
}

func (o AgentOptions) FilterByK8s() bool {
	return o.PodName != ""
}

func getPodNameFilter(raw string) (name, ns string) {
	if !strings.Contains(raw, ".") {
		return raw, "default"
	}
	index := strings.LastIndex(raw, ".")
	return raw[:index], raw[index+1:]
}

func getEndpoint(raw string) string {
	if strings.HasPrefix(raw, "http") {
		return raw
	}
	if strings.HasPrefix(raw, "unix://") {
		return raw
	}
	return fmt.Sprintf("unix://%s", raw)
}

func ValidateAndRepairOptions(options AgentOptions) AgentOptions {
	var newOptions = options
	if newOptions.Stopper == nil {
		newOptions.Stopper = make(chan os.Signal)
	}
	if newOptions.ProcessorsNum == 0 {
		newOptions.ProcessorsNum = runtime.NumCPU()
	}
	if newOptions.MessageFilter == nil {
		newOptions.MessageFilter = protocol.BaseFilter{}
	}
	if newOptions.PerfEventBufferSizeForData <= 0 {
		newOptions.PerfEventBufferSizeForData = perfEventDataBufferSize
	}
	if newOptions.PerfEventBufferSizeForEvent <= 0 {
		newOptions.PerfEventBufferSizeForEvent = perfEventControlBufferSize
	}
	if newOptions.PodName != "" {
		newOptions.PodName, newOptions.PodNameSpace = getPodNameFilter(newOptions.PodName)
	}
	if newOptions.DockerEndpoint != "" {
		newOptions.DockerEndpoint = getEndpoint(newOptions.DockerEndpoint)
	}
	if newOptions.CriRuntimeEndpoint != "" {
		newOptions.CriRuntimeEndpoint = getEndpoint(newOptions.CriRuntimeEndpoint)
	}
	newOptions.WatchOptions.Init()
	newOptions.LoadPorgressChannel = make(chan string, 10)
	return newOptions
}
