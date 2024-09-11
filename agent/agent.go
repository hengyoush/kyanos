package agent

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"kyanos/agent/analysis"
	"kyanos/agent/compatible"
	"kyanos/agent/conn"
	"kyanos/agent/protocol"
	"kyanos/agent/render"
	"kyanos/bpf"
	"kyanos/common"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jefurry/logrus"
	"github.com/spf13/viper"
)

type LoadBpfProgramFunction func(programs interface{}) *list.List
type SyscallEventHook func(evt *bpf.SyscallEventData)
type ConnEventHook func(evt *bpf.AgentConnEvtT)
type KernEventHook func(evt *bpf.AgentKernEvt)
type InitCompletedHook func()
type ConnManagerInitHook func(*conn.ConnManager)

var log *logrus.Logger = common.Log

const perfEventDataBufferSize = 30 * 1024 * 1024
const perfEventControlBufferSize = 2 * 1024 * 1024

type AgentOptions struct {
	Stopper                chan os.Signal
	CustomSyscallEventHook SyscallEventHook
	CustomConnEventHook    ConnEventHook
	CustomKernEventHook    KernEventHook
	InitCompletedHook      InitCompletedHook
	ConnManagerInitHook    ConnManagerInitHook
	LoadBpfProgramFunction LoadBpfProgramFunction
	ProcessorsNum          int
	MessageFilter          protocol.ProtocolFilter
	LatencyFilter          protocol.LatencyFilter
	TraceSide              common.SideEnum
	IfName                 string
	BTFFilePath            string
	BPFVerifyLogSize       int
	protocol.SizeFilter
	AnalysisEnable bool
	analysis.AnalysisOptions
	PerfEventBufferSizeForData  int
	PerfEventBufferSizeForEvent int
}

func validateAndRepairOptions(options AgentOptions) AgentOptions {
	var newOptions = options
	if newOptions.Stopper == nil {
		newOptions.Stopper = make(chan os.Signal)
	}
	if newOptions.ProcessorsNum == 0 {
		newOptions.ProcessorsNum = runtime.NumCPU()
	}
	if newOptions.MessageFilter == nil {
		newOptions.MessageFilter = protocol.NoopFilter{}
	}
	if newOptions.BPFVerifyLogSize <= 0 {
		newOptions.BPFVerifyLogSize = 1 * 1024 * 1024
	}
	return newOptions
}

func SetupAgent(options AgentOptions) {
	options = validateAndRepairOptions(options)
	common.LaunchEpochTime = GetMachineStartTimeNano()
	stopper := options.Stopper
	connManager := conn.InitConnManager()
	if options.ConnManagerInitHook != nil {
		options.ConnManagerInitHook(connManager)
	}
	statRecorder := analysis.InitStatRecorder()

	var recordsChannel chan *analysis.AnnotatedRecord = nil
	if options.AnalysisEnable {
		recordsChannel = make(chan *analysis.AnnotatedRecord, 1000)
		resultChannel := make(chan []*analysis.ConnStat, 1000)
		renderStopper := make(chan int)
		analyzer := analysis.CreateAnalyzer(recordsChannel, &options.AnalysisOptions, resultChannel, renderStopper)
		go analyzer.Run()

		render := render.CreateRender(resultChannel, renderStopper, analyzer.AnalysisOptions)
		go render.Run()
	}

	pm := conn.InitProcessorManager(options.ProcessorsNum, connManager, options.MessageFilter, options.LatencyFilter, options.SizeFilter, options.TraceSide)
	conn.RecordFunc = func(r protocol.Record, c *conn.Connection4) error {
		return statRecorder.ReceiveRecord(r, c, recordsChannel)
	}
	conn.OnCloseRecordFunc = func(c *conn.Connection4) error {
		statRecorder.RemoveRecord(c.TgidFd)
		return nil
	}

	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Remove memlock:", err)
	}

	kernelVersion := compatible.GetCurrentKernelVersion()

	var links *list.List
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs any
	var spec *ebpf.CollectionSpec
	var err error
	var collectionOptions *ebpf.CollectionOptions
	if options.BTFFilePath != "" {
		btfPath, err := btf.LoadSpec(options.BTFFilePath)
		if err != nil {
			log.Fatalf("can't load btf spec: %v", err)
		}
		collectionOptions = &ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				KernelTypes: btfPath,
				LogSize:     options.BPFVerifyLogSize,
			},
		}
	} else {
		collectionOptions = nil
	}
	if !kernelVersion.SupportCapability(compatible.SupportRingBuffer) {
		objs = &bpf.AgentOldObjects{}
		spec, err = bpf.LoadAgentOld()
		if err != nil {
			log.Fatal("load Agent error:", err)
		}
		log.Warnf("rb type: %d", spec.Maps["rb"].Type)
	} else {
		objs = &bpf.AgentObjects{}
		spec, err = bpf.LoadAgent()
		if err != nil {
			log.Fatal("load Agent error:", err)
		}
	}
	bpf.Objs = objs

	filterFunctions(spec, kernelVersion)
	err = spec.LoadAndAssign(objs, collectionOptions)

	agentOldObjects, ok := objs.(*bpf.AgentOldObjects)
	agentObjects, ok := objs.(*bpf.AgentObjects)
	if ok {

	}

	if err != nil {
		err = errors.Unwrap(errors.Unwrap(err))
		inner_err, ok := err.(*ebpf.VerifierError)
		if ok {
			inner_err.Truncated = false
			log.Errorf("loadAgentObjects: %+v", inner_err)
		} else {
			log.Errorf("loadAgentObjects: %+v", err)
		}
		return
	}

	defer func() {
		var closer io.Closer
		if !kernelVersion.SupportCapability(compatible.SupportRingBuffer) {
			agentOldObjects := objs.(*bpf.AgentOldObjects)
			closer = agentOldObjects
		} else {
			agentObjects := objs.(*bpf.AgentObjects)
			closer = agentObjects
		}

		closer.Close()
	}()
	var validateResult = setAndValidateParameters()
	if !kernelVersion.SupportCapability(compatible.SupportRingBuffer) {
		if options.LoadBpfProgramFunction != nil {
			links = options.LoadBpfProgramFunction(agentOldObjects.AgentOldPrograms)
		} else {
			links = attachBpfProgs(agentOldObjects.AgentOldPrograms, options.IfName, kernelVersion, options)
		}
	} else {

		if options.LoadBpfProgramFunction != nil {
			links = options.LoadBpfProgramFunction(agentObjects.AgentPrograms)
		} else {
			links = attachBpfProgs(agentObjects.AgentPrograms, options.IfName, kernelVersion, options)
		}
	}

	if !kernelVersion.SupportCapability(compatible.SupportXDP) {
		enabledXdp := bpf.AgentControlValueIndexTKEnabledXdpIndex
		var enableXdpValue int64 = 0
		bpf.GetMap("ControlValues").Update(&enabledXdp, &enableXdpValue, ebpf.UpdateAny)
	}
	if !validateResult {
		return
	}

	defer func() {
		for e := links.Front(); e != nil; e = e.Next() {
			if e.Value == nil {
				continue
			}
			if l, ok := e.Value.(link.Link); ok {
				err := l.Close()
				if err != nil {
					info, _ := l.Info()
					log.Errorf("Fail to close link for: %v\n", info)
				}
			}
		}
		log.Debugln("All links closed!")
	}()
	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	stop := false
	readers, err := setupReaders(options, kernelVersion, objs)
	if err != nil {
		for _, reader := range readers {
			reader.Close()
		}
		return
	}

	go func() {
		<-stopper
		common.SendStopSignal()
		log.Debugln("stop!")
		for _, reader := range readers {
			if err := reader.Close(); err != nil {
				log.Fatalf("closing reader(%v) error: %s", reader, err)
			}
		}
		pm.StopAll()
		stop = true
	}()

	log.Info("Waiting for events..")

	startReaders(options, kernelVersion, pm, readers)

	if options.InitCompletedHook != nil {
		options.InitCompletedHook()
	}
	for !stop {
		time.Sleep(time.Second * 1)
	}
	log.Infoln("Kyanos Stopped")
	return
}

func startReaders(options AgentOptions, kernel compatible.KernelVersion, pm *conn.ProcessorManager, readers []io.Closer) {
	if kernel.SupportCapability(compatible.SupportRingBuffer) {
		// syscall
		startRingbufferReader(readers[0], func(r ringbuf.Record) error {
			return handleSyscallEvt(r.RawSample, pm, options.ProcessorsNum, options.CustomSyscallEventHook)
		})
		// kernel event
		startRingbufferReader(readers[1], func(r ringbuf.Record) error {
			return handleKernEvt(r.RawSample, pm, options.ProcessorsNum, options.CustomKernEventHook)
		})
		// conn event
		startRingbufferReader(readers[2], func(r ringbuf.Record) error {
			return handleConnEvt(r.RawSample, pm, options.ProcessorsNum, options.CustomConnEventHook)
		})
	} else {
		startPerfeventReader(readers[0], func(r perf.Record) error {
			return handleSyscallEvt(r.RawSample, pm, options.ProcessorsNum, options.CustomSyscallEventHook)
		})
		startPerfeventReader(readers[1], func(r perf.Record) error {
			return handleKernEvt(r.RawSample, pm, options.ProcessorsNum, options.CustomKernEventHook)
		})
		startPerfeventReader(readers[2], func(r perf.Record) error {
			return handleConnEvt(r.RawSample, pm, options.ProcessorsNum, options.CustomConnEventHook)
		})
	}
}

func setupReaders(options AgentOptions, kernel compatible.KernelVersion, objs any) ([]io.Closer, error) {
	closers := make([]io.Closer, 0)
	syscallDataReader, err := setupReader(options, kernel, objs, "SyscallRb", true)
	if err != nil {
		return nil, err
	}
	closers = append(closers, syscallDataReader)

	kernEventReader, err := setupReader(options, kernel, objs, "Rb", false)
	if err != nil {
		return closers, err
	}
	closers = append(closers, kernEventReader)

	connEvtReader, err := setupReader(options, kernel, objs, "ConnEvtRb", false)
	if err != nil {
		return closers, err
	}
	closers = append(closers, connEvtReader)
	return closers, nil
}

func setupReader(options AgentOptions, kernel compatible.KernelVersion, objs any, mapName string, isDataBuffer bool) (io.Closer, error) {
	if kernel.SupportCapability(compatible.SupportRingBuffer) {
		return ringbuf.NewReader(bpf.GetMapByObjs(mapName, objs))
	} else {
		if isDataBuffer {
			return perf.NewReader(bpf.GetMapByObjs(mapName, objs), options.PerfEventBufferSizeForData)
		} else {
			return perf.NewReader(bpf.GetMapByObjs(mapName, objs), options.PerfEventBufferSizeForEvent)
		}
	}
}

func startRingbufferReader(reader io.Closer, consumeFunction func(ringbuf.Record) error) {
	ringbuffer := reader.(*ringbuf.Reader)
	go func() {
		for {
			record, err := ringbuffer.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					log.Debug("[dataReader] Received signal, exiting..")
					return
				}
				log.Debugf("[dataReader] reading from reader: %s\n", err)
				continue
			}
			if err := consumeFunction(record); err != nil {
				log.Errorf("[dataReader] handleKernEvt err: %s\n", err)
				continue
			}
		}
	}()
}

func startPerfeventReader(reader io.Closer, consumeFunction func(perf.Record) error) {
	perfReader := reader.(*perf.Reader)
	go func() {
		for {
			record, err := perfReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					log.Debug("[dataReader] Received signal, exiting..")
					return
				}
				log.Debugf("[dataReader] reading from reader: %s\n", err)
				continue
			}
			if err := consumeFunction(record); err != nil {
				log.Errorf("[dataReader] handleKernEvt err: %s\n", err)
				continue
			}
		}
	}()
}

func setAndValidateParameters() bool {
	var controlValues *ebpf.Map = bpf.GetMap("ControlValues")
	var enabledRemotePortMap *ebpf.Map = bpf.GetMap("EnabledRemotePortMap")
	var enabledRemoteIpv4Map *ebpf.Map = bpf.GetMap("EnabledRemoteIpv4Map")
	var enabledLocalPortMap *ebpf.Map = bpf.GetMap("EnabledLocalPortMap")

	if targetPid := viper.GetInt64(common.FilterPidVarName); targetPid > 0 {
		log.Infoln("filter for pid: ", targetPid)
		controlValues.Update(bpf.AgentControlValueIndexTKTargetTGIDIndex, targetPid, ebpf.UpdateAny)
	}

	remotePorts := viper.GetStringSlice(common.RemotePortsVarName)
	oneKey := uint16(1)
	zeroValue := uint8(0)
	if len(remotePorts) > 0 {
		log.Infoln("filter for remote ports: ", remotePorts)
		err := enabledRemotePortMap.Update(&oneKey, &zeroValue, ebpf.UpdateAny)
		if err != nil {
			log.Errorln("Update EnabledRemotePortMap failed: ", err)
		}
		for _, each := range remotePorts {
			portInt, err := strconv.Atoi(each)
			if err != nil || portInt <= 0 {
				log.Errorf("Invalid remote port : %s\n", each)
				return false
			}
			portNumber := uint16(portInt)
			err = enabledRemotePortMap.Update(&portNumber, &zeroValue, ebpf.UpdateAny)
			if err != nil {
				log.Errorln("Update EnabledRemotePortMap failed: ", err)
			}
		}
	}

	remoteIps := viper.GetStringSlice(common.RemoteIpsVarName)
	if len(remoteIps) > 0 {
		log.Infoln("filter for remote ips: ", remoteIps)
		oneKeyU32 := uint32(1)
		err := enabledRemoteIpv4Map.Update(&oneKeyU32, &zeroValue, ebpf.UpdateAny)
		if err != nil {
			log.Errorln("Update EnabledRemoteIpv4Map failed: ", err)
		}
		for _, each := range remoteIps {
			ipInt32, err := common.IPv4ToUint32(each)
			if err != nil {
				log.Errorf("IPv4ToUint32 parse failed, ip string is: %s, err: %v", each, err)
				return false
			} else {
				log.Debugln("Update EnabledRemoteIpv4Map, key: ", ipInt32, common.IntToIP(ipInt32))
				err = enabledRemoteIpv4Map.Update(&ipInt32, &zeroValue, ebpf.UpdateAny)
				if err != nil {
					log.Errorln("Update EnabledRemoteIpv4Map failed: ", err)
				}
			}
		}
	}

	localPorts := viper.GetStringSlice(common.LocalPortsVarName)
	if len(localPorts) > 0 {
		log.Infoln("filter for local ports: ", localPorts)
		err := enabledLocalPortMap.Update(&oneKey, &oneKey, ebpf.UpdateAny)
		if err != nil {
			log.Errorln("Update EnabledLocalPortMap failed: ", err)
		}
		for _, each := range localPorts {
			portInt, err := strconv.Atoi(each)
			if err != nil || portInt <= 0 {
				log.Errorf("Invalid local port : %s\n", each)
				return false
			}
			portNumber := uint16(portInt)
			err = enabledLocalPortMap.Update(&portNumber, &zeroValue, ebpf.UpdateAny)
			if err != nil {
				log.Errorln("Update EnabledLocalPortMap failed: ", err)
			}
		}
	}

	return true
}

func handleConnEvt(record []byte, pm *conn.ProcessorManager, processorsNum int, customConnEventHook ConnEventHook) error {
	var event bpf.AgentConnEvtT
	err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event)
	if err != nil {
		return err
	}

	tgidFd := uint64(event.ConnInfo.ConnId.Upid.Pid)<<32 | uint64(event.ConnInfo.ConnId.Fd)
	p := pm.GetProcessor(int(tgidFd) % processorsNum)
	if customConnEventHook != nil {
		customConnEventHook(&event)
	}
	p.AddConnEvent(&event)
	return nil
}
func handleSyscallEvt(record []byte, pm *conn.ProcessorManager, processorsNum int, customSyscallEventHook SyscallEventHook) error {
	// 首先看这个连接上有没有堆积的请求，如果有继续堆积
	// 如果没有作为新的请求
	event := new(bpf.SyscallEventData)
	err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event.SyscallEvent)
	if err != nil {
		return err
	}
	msgSize := event.SyscallEvent.BufSize
	buf := make([]byte, msgSize)
	headerSize := uint(unsafe.Sizeof(event.SyscallEvent)) - 4
	err = binary.Read(bytes.NewBuffer(record[headerSize:]), binary.LittleEndian, &buf)
	if err != nil {
		return err
	}
	event.Buf = buf

	tgidFd := event.SyscallEvent.Ke.ConnIdS.TgidFd
	p := pm.GetProcessor(int(tgidFd) % processorsNum)
	if customSyscallEventHook != nil {
		customSyscallEventHook(event)
	}
	p.AddSyscallEvent(event)
	return nil
}
func handleKernEvt(record []byte, pm *conn.ProcessorManager, processorsNum int, customKernEventHook KernEventHook) error {
	var event bpf.AgentKernEvt
	err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event)
	if err != nil {
		return err
	}
	tgidFd := event.ConnIdS.TgidFd
	p := pm.GetProcessor(int(tgidFd) % processorsNum)
	if customKernEventHook != nil {
		customKernEventHook(&event)
	}
	p.AddKernEvent(&event)
	return nil
}

func attachBpfProgs(programs any, ifName string, kernelVersion compatible.KernelVersion, options AgentOptions) *list.List {
	linkList := list.New()

	if kernelVersion.SupportCapability(compatible.SupportXDP) {
		l, err := bpf.AttachXdpWithSpecifiedIfName(programs, options.IfName)
		if err != nil {
			log.Warnf("Attach XDP program failed, fallbacking...")
		} else {
			linkList.PushBack(l)
		}
	}

	if kernelVersion.SupportCapability(compatible.SupportRawTracepoint) {
		l, err := bpf.AttachRawTracepointTcpDestroySockEntry(programs)
		if err != nil {
			log.Warnf("Attach TCP destroy raw tracepoint failed, fallbacking...")
		} else {
			linkList.PushBack(l)
		}
	}

	for _, functions := range kernelVersion.InstrumentFunctions {
		for idx, function := range functions {
			var err error
			var l link.Link
			if function.IsKprobe() {
				l, err = bpf.Kprobe(function.GetKprobeName(), bpf.GetProgram(programs, function.BPFGoProgName))
			} else if function.IsTracepoint() {
				l, err = bpf.Tracepoint(function.GetTracepointGroupName(), function.GetTracepointName(),
					bpf.GetProgram(programs, function.BPFGoProgName))
			} else if function.IsKRetprobe() {
				l, err = bpf.Kretprobe(function.GetKprobeName(), bpf.GetProgram(programs, function.BPFGoProgName))
			} else {
				panic(fmt.Sprintf("invalid program type: %v", function))
			}
			if err != nil {
				if idx == len(functions)-1 {
					log.Fatalf("Attach failed: %v, functions: %v", err, functions)
				}
			} else {
				linkList.PushBack(l)
			}
		}
	}

	linkList.PushBack(bpf.AttachSyscallAcceptEntry(programs))
	linkList.PushBack(bpf.AttachSyscallAcceptExit(programs))

	linkList.PushBack(bpf.AttachSyscallSockAllocExit(programs))

	linkList.PushBack(bpf.AttachSyscallConnectEntry(programs))
	linkList.PushBack(bpf.AttachSyscallConnectExit(programs))

	linkList.PushBack(bpf.AttachSyscallCloseEntry(programs))
	linkList.PushBack(bpf.AttachSyscallCloseExit(programs))

	linkList.PushBack(bpf.AttachSyscallWriteEntry(programs))
	linkList.PushBack(bpf.AttachSyscallWriteExit(programs))

	linkList.PushBack(bpf.AttachSyscallSendMsgEntry(programs))
	linkList.PushBack(bpf.AttachSyscallSendMsgExit(programs))

	linkList.PushBack(bpf.AttachSyscallRecvMsgEntry(programs))
	linkList.PushBack(bpf.AttachSyscallRecvMsgExit(programs))

	linkList.PushBack(bpf.AttachSyscallWritevEntry(programs))
	linkList.PushBack(bpf.AttachSyscallWritevExit(programs))

	linkList.PushBack(bpf.AttachSyscallSendtoEntry(programs))
	linkList.PushBack(bpf.AttachSyscallSendtoExit(programs))

	linkList.PushBack(bpf.AttachSyscallReadEntry(programs))
	linkList.PushBack(bpf.AttachSyscallReadExit(programs))

	linkList.PushBack(bpf.AttachSyscallReadvEntry(programs))
	linkList.PushBack(bpf.AttachSyscallReadvExit(programs))

	linkList.PushBack(bpf.AttachSyscallRecvfromEntry(programs))
	linkList.PushBack(bpf.AttachSyscallRecvfromExit(programs))

	linkList.PushBack(bpf.AttachKProbeSecuritySocketRecvmsgEntry(programs))
	linkList.PushBack(bpf.AttachKProbeSecuritySocketSendmsgEntry(programs))

	return linkList
}

func filterFunctions(coll *ebpf.CollectionSpec, kernelVersion compatible.KernelVersion) {
	finalCProgNames := make([]string, 0)

	if kernelVersion.SupportCapability(compatible.SupportXDP) {
		finalCProgNames = append(finalCProgNames, bpf.XDPProgramName)
	}
	if kernelVersion.SupportCapability(compatible.SupportRawTracepoint) {
		finalCProgNames = append(finalCProgNames, bpf.TcpDestroySocketProgName)
	}
	for step := bpf.AgentStepTStart; step < bpf.AgentStepTEnd; step++ {
		functions, ok := kernelVersion.InstrumentFunctions[step]
		if ok {
			for _, function := range functions {
				finalCProgNames = append(finalCProgNames, bpf.GoProgName2CProgName[function.BPFGoProgName])
			}
		}
	}

	finalCProgNames = append(finalCProgNames, bpf.SyscallExtraProgNames...)
	for name := range coll.Programs {
		if strings.HasPrefix(name, "tracepoint__syscalls") {
			finalCProgNames = append(finalCProgNames, name)
		}
	}

	needsDelete := make([]string, 0)
	for cProgName, _ := range coll.Programs {
		if slices.Index(finalCProgNames, cProgName) == -1 {
			needsDelete = append(needsDelete, cProgName)
		}
	}
	for _, each := range needsDelete {
		coll.Programs[each] = socketFilterSpec
	}
}

var socketFilterSpec = &ebpf.ProgramSpec{
	Name: "test",
	Type: ebpf.Kprobe,
	Instructions: asm.Instructions{
		asm.LoadImm(asm.R0, 2, asm.DWord),
		asm.Return(),
	},
	License: "MIT",
}
