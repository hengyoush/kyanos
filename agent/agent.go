package agent

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"errors"
	"io"
	"kyanos/agent/analysis"
	"kyanos/agent/conn"
	"kyanos/agent/protocol"
	"kyanos/agent/render"
	"kyanos/bpf"
	"kyanos/common"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
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

const perfEventDataBufferSize = 100 * 1024 * 1024
const perfEventControlBufferSize = 10 * 1024 * 1024

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
	protocol.SizeFilter
	AnalysisEnable bool
	analysis.AnalysisOptions
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

	var links *list.List
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs any
	var spec *ebpf.CollectionSpec
	var err error
	if common.NeedsRunningInCompatibleMode() {
		objs = &bpf.AgentOldObjects{}
		spec, err = bpf.LoadAgentOld()
		if err != nil {
			log.Fatal("load Agent error:", err)
		}
		err = spec.LoadAndAssign(objs, nil)
	} else {
		objs = &bpf.AgentObjects{}
		spec, err = bpf.LoadAgent()
		if err != nil {
			log.Fatal("load Agent error:", err)
		}
		err = spec.LoadAndAssign(objs, nil)
	}
	bpf.Objs = objs

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
		if common.NeedsRunningInCompatibleMode() {
			agentOldObjects := objs.(*bpf.AgentOldObjects)
			closer = agentOldObjects
		} else {
			agentObjects := objs.(*bpf.AgentObjects)
			closer = agentObjects
		}

		closer.Close()
	}()
	var validateResult bool
	if common.NeedsRunningInCompatibleMode() {
		agentOldObjects := objs.(*bpf.AgentOldObjects)
		validateResult = setAndValidateParameters(agentOldObjects.AgentOldMaps)
		if options.LoadBpfProgramFunction != nil {
			links = options.LoadBpfProgramFunction(agentOldObjects.AgentOldPrograms)
		} else {
			links = attachBpfProgs(agentOldObjects.AgentOldPrograms, options.IfName)
		}
		if !common.EnabledXdp() {
			enabledXdp := bpf.AgentControlValueIndexTKEnabledXdpIndex
			var enableXdpValue int64 = 0
			agentOldObjects.ControlValues.Update(&enabledXdp, &enableXdpValue, ebpf.UpdateAny)
		}
	} else {
		agentObjects := objs.(*bpf.AgentObjects)
		validateResult = setAndValidateParameters(agentObjects.AgentMaps)

		if options.LoadBpfProgramFunction != nil {
			links = options.LoadBpfProgramFunction(agentObjects.AgentPrograms)
		} else {
			links = attachBpfProgs(agentObjects.AgentPrograms, options.IfName)
		}
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
	if common.NeedsRunningInCompatibleMode() {
		oldMaps := objs.(*bpf.AgentOldObjects).AgentOldMaps
		syscallDataReader, err := perf.NewReader(oldMaps.SyscallRb, perfEventDataBufferSize)
		if err != nil {
			log.Fatal("new syscall data reader perf err:", err)
			return
		}
		defer syscallDataReader.Close()

		dataReader, err := perf.NewReader(oldMaps.Rb, perfEventControlBufferSize)
		if err != nil {
			log.Fatal("new dataReader perf err:", err)
			return
		}
		defer dataReader.Close()

		connEvtReader, err := perf.NewReader(oldMaps.ConnEvtRb, perfEventControlBufferSize)
		if err != nil {
			log.Fatal("new connEvtReader perf err:", err)
			return
		}
		defer connEvtReader.Close()

		go func() {
			<-stopper
			common.SendStopSignal()
			log.Debugln("stop!")
			if err := dataReader.Close(); err != nil {
				log.Fatalf("closing dataReader error: %s", err)
			}
			if err := connEvtReader.Close(); err != nil {
				log.Fatalf("closing connEvtReader error: %s", err)
			}
			if err := syscallDataReader.Close(); err != nil {
				log.Fatalf("closing syscallDataReader error: %s", err)
			}
			pm.StopAll()
			stop = true
		}()

		log.Info("Waiting for events..")

		go func() {
			for {
				record, err := dataReader.Read()
				if err != nil {
					if errors.Is(err, perf.ErrClosed) {
						log.Debug("[dataReader] Received signal, exiting..")
						return
					}
					log.Debugf("[dataReader] reading from reader: %s\n", err)
					continue
				}

				if err := handleKernEvt(record.RawSample, pm, options.ProcessorsNum, options.CustomKernEventHook); err != nil {
					log.Errorf("[dataReader] handleKernEvt err: %s\n", err)
					continue
				}

			}
		}()

		go func() {
			for {
				record, err := syscallDataReader.Read()
				if err != nil {
					if errors.Is(err, perf.ErrClosed) {
						log.Debugf("[syscallDataReader] Received signal, exiting..")
						return
					}
					log.Debugf("[syscallDataReader] reading from reader: %s\n", err)
					continue
				}
				if err := handleSyscallEvt(record.RawSample, pm, options.ProcessorsNum, options.CustomSyscallEventHook); err != nil {
					log.Errorf("[syscallDataReader] handleSyscallEvt err: %s\n", err)
					continue
				}
			}
		}()

		go func() {
			for {
				record, err := connEvtReader.Read()
				if err != nil {
					if errors.Is(err, perf.ErrClosed) {
						log.Debugln("[connEvtReader] Received signal, exiting..")
						return
					}
					log.Debugf("[connEvtReader] reading from reader: %s\n", err)
					continue
				}
				if err := handleConnEvt(record.RawSample, pm, options.ProcessorsNum, options.CustomConnEventHook); err != nil {
					log.Errorf("[connEvtReader] handleKernEvt err: %s\n", err)
					continue
				}
			}
		}()
	} else {
		maps := objs.(*bpf.AgentObjects).AgentMaps
		// kernel >= 5.8
		syscallDataReader, err := ringbuf.NewReader(maps.SyscallRb)
		if err != nil {
			log.Fatal("new syscall data reader ringbuffer err:", err)
			return
		}
		defer syscallDataReader.Close()

		dataReader, err := ringbuf.NewReader(maps.Rb)
		if err != nil {
			log.Error("new dataReader ringbuffer err:", err)
			return
		}
		defer dataReader.Close()

		connEvtReader, err := ringbuf.NewReader(maps.ConnEvtRb)
		if err != nil {
			log.Error("new connEvtReader ringbuffer err:", err)
			return
		}
		defer connEvtReader.Close()

		go func() {
			<-stopper
			common.SendStopSignal()
			log.Debugln("stop!")
			if err := dataReader.Close(); err != nil {
				log.Fatalf("closing dataReader error: %s", err)
			}
			if err := connEvtReader.Close(); err != nil {
				log.Fatalf("closing connEvtReader error: %s", err)
			}
			if err := syscallDataReader.Close(); err != nil {
				log.Fatalf("closing syscallDataReader error: %s", err)
			}
			pm.StopAll()
			stop = true
		}()

		log.Info("Waiting for events..")

		// https://github.com/cilium/ebpf/blob/main/examples/ringbuffer/ringbuffer.c
		go func() {
			for {
				record, err := dataReader.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						log.Debug("[dataReader] Received signal, exiting..")
						return
					}
					log.Debugf("[dataReader] reading from reader: %s\n", err)
					continue
				}

				if err := handleKernEvt(record.RawSample, pm, options.ProcessorsNum, options.CustomKernEventHook); err != nil {
					log.Errorf("[dataReader] handleKernEvt err: %s\n", err)
					continue
				}

			}
		}()

		go func() {
			for {
				record, err := syscallDataReader.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						log.Debugf("[syscallDataReader] Received signal, exiting..")
						return
					}
					log.Debugf("[syscallDataReader] reading from reader: %s\n", err)
					continue
				}
				if err := handleSyscallEvt(record.RawSample, pm, options.ProcessorsNum, options.CustomSyscallEventHook); err != nil {
					log.Errorf("[syscallDataReader] handleSyscallEvt err: %s\n", err)
					continue
				}
			}
		}()

		go func() {
			for {
				record, err := connEvtReader.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						log.Debugln("[connEvtReader] Received signal, exiting..")
						return
					}
					log.Debugf("[connEvtReader] reading from reader: %s\n", err)
					continue
				}
				if err := handleConnEvt(record.RawSample, pm, options.ProcessorsNum, options.CustomConnEventHook); err != nil {
					log.Errorf("[connEvtReader] handleKernEvt err: %s\n", err)
					continue
				}
			}
		}()
	}

	if options.InitCompletedHook != nil {
		options.InitCompletedHook()
	}
	for !stop {
		time.Sleep(time.Second * 1)
	}
	log.Infoln("Kyanos Stopped")
	return
}

func setAndValidateParameters(maps any) bool {
	var controlValues *ebpf.Map
	var enabledRemotePortMap *ebpf.Map
	var enabledRemoteIpv4Map *ebpf.Map
	var enabledLocalPortMap *ebpf.Map
	if common.NeedsRunningInCompatibleMode() {
		oldMaps := maps.(bpf.AgentOldMaps)
		controlValues = oldMaps.ControlValues
		enabledRemotePortMap = oldMaps.EnabledRemotePortMap
		enabledRemoteIpv4Map = oldMaps.EnabledRemoteIpv4Map
		enabledLocalPortMap = oldMaps.EnabledLocalPortMap
	} else {
		newMaps := maps.(bpf.AgentMaps)
		controlValues = newMaps.ControlValues
		enabledRemotePortMap = newMaps.EnabledRemotePortMap
		enabledRemoteIpv4Map = newMaps.EnabledRemoteIpv4Map
		enabledLocalPortMap = newMaps.EnabledLocalPortMap
	}

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

func attachBpfProgs(programs any, ifName string) *list.List {
	linkList := list.New()

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

	linkList.PushBack(bpf.AttachRawTracepointTcpDestroySockEntry(programs))
	linkList.PushBack(bpf.AttachKProbeIpQueueXmitEntry(programs))
	linkList.PushBack(bpf.AttachKProbeDevQueueXmitEntry(programs))
	linkList.PushBack(bpf.AttachKProbeDevHardStartXmitEntry(programs))

	linkList.PushBack(bpf.AttachKProbIpRcvCoreEntry(programs))
	linkList.PushBack(bpf.AttachKProbeTcpV4DoRcvEntry(programs))
	linkList.PushBack(bpf.AttachKProbeSkbCopyDatagramIterEntry(programs))
	linkList.PushBack(bpf.AttachTracepointNetifReceiveSkb(programs))
	if common.EnabledXdp() {
		linkList.PushBack(bpf.AttachXdpWithSpecifiedIfName(programs, ifName))
	}
	return linkList
}
