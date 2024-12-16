package loader

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	ac "kyanos/agent/common"
	"kyanos/agent/compatible"
	"kyanos/agent/uprobe"
	"kyanos/bpf"
	"kyanos/common"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/shirou/gopsutil/process"
	"github.com/spf13/viper"
)

type BPF struct {
	Links *list.List        // close
	Objs  *bpf.AgentObjects // close
	Err   error
}

func (b *BPF) Close() {
	if b.Objs != nil {
		b.Objs.Close()
	}

	if b.Links != nil {
		for e := b.Links.Front(); e != nil; e = e.Next() {
			if e.Value == nil {
				continue
			}
			if l, ok := e.Value.(link.Link); ok {
				err := l.Close()
				if err != nil {
					info, _ := l.Info()
					common.AgentLog.Errorf("Fail to close link for: %v\n", info)
				}
			}
		}
	}
	common.AgentLog.Debugln("All links closed!")
}

func LoadBPF(options *ac.AgentOptions) (*BPF, error) {
	var objs *bpf.AgentObjects
	var spec *ebpf.CollectionSpec
	var collectionOptions *ebpf.CollectionOptions
	var err error
	var bf *BPF = &BPF{}

	if err := features.HaveProgramType(ebpf.Kprobe); errors.Is(err, ebpf.ErrNotSupported) {
		common.AgentLog.Errorf("Require oldest kernel version is 3.10.0-957, pls check your kernel version by `uname -r`\n")
		return nil, err
	}

	if os.Geteuid() != 0 {
		common.AgentLog.Error("Kyanos requires root privileges to run. Please run kyanos with sudo.")
		return nil, err
	}

	btfSpec, err := loadBTFSpec(options)
	if err != nil {
		return nil, err
	}
	collectionOptions = &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: btfSpec,
		},
	}

	ac.CollectionOpts = collectionOptions
	if !options.Kv.SupportCapability(compatible.SupportFilterByContainer) {
		// if true {
		lagacyobjs := &bpf.AgentLagacyKernel310Objects{}
		spec, err = bpf.LoadAgentLagacyKernel310()
		if err != nil {
			common.AgentLog.Fatal("load Agent error:", err)
		}
		filterFunctions(spec, *options.Kv)
		err = spec.LoadAndAssign(lagacyobjs, collectionOptions)
		objs = AgentObjectsFromLagacyKernel310(lagacyobjs)
	} else {
		objs = &bpf.AgentObjects{}
		spec, err = bpf.LoadAgent()
		if err != nil {
			common.AgentLog.Fatal("load Agent error:", err)
		}
		filterFunctions(spec, *options.Kv)
		err = spec.LoadAndAssign(objs, collectionOptions)
	}
	bf.Objs = objs
	bpf.Objs = objs
	options.LoadPorgressChannel <- "🍎 Loaded eBPF maps & programs."

	if err != nil {
		err = errors.Unwrap(errors.Unwrap(err))
		inner_err, ok := err.(*ebpf.VerifierError)
		if ok {
			common.AgentLog.Errorf("loadAgentObjects: %+v", inner_err)
		} else {
			common.AgentLog.Errorf("loadAgentObjects: %+v", err)
		}
		return nil, err
	}

	var validateResult = setAndValidateParameters(options.Ctx, options)
	if !validateResult {
		return nil, fmt.Errorf("validate param failed!")
	}
	options.LoadPorgressChannel <- "🍓 Setup traffic filters"

	bpf.PullProcessExitEvents(options.Ctx, []chan *bpf.AgentProcessExitEvent{initProcExitEventChannel(options.Ctx)})

	return bf, nil
}

func (bf *BPF) AttachProgs(options *ac.AgentOptions) error {
	var links *list.List
	if options.LoadBpfProgramFunction != nil {
		links = options.LoadBpfProgramFunction()
	} else {
		links = attachBpfProgs(options.IfName, options.Kv, options)
	}

	options.LoadPorgressChannel <- "🍆 Attached base eBPF programs."

	if !options.DisableOpensslUprobe {
		attachOpenSslUprobes(links, options, options.Kv, bf.Objs)
		options.LoadPorgressChannel <- "🍕 Attached ssl eBPF programs."
	}
	attachNfFunctions(links)
	options.LoadPorgressChannel <- "🥪 Attached conntrack eBPF programs."
	bf.Links = links
	return nil
}

// writeToFile writes the []uint8 slice to a specified file in the system's temp directory.
// If the temp directory does not exist, it creates a ".kyanos" directory in the current directory.
func writeToFile(data []uint8, filename string) (string, error) {
	// Get the system's temp directory
	tempDir := os.TempDir()

	// Check if the temp directory exists
	if _, err := os.Stat(tempDir); os.IsNotExist(err) {
		// Create a ".kyanos" directory in the current directory
		tempDir = "."
	}

	// Create the file path
	filePath := filepath.Join(tempDir, filename)

	// Write the byte slice to the file
	err := os.WriteFile(filePath, data, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write file: %v", err)
	}

	// Return the absolute path of the file
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %v", err)
	}

	return absPath, nil
}

func AgentObjectsFromLagacyKernel310(legacy *bpf.AgentLagacyKernel310Objects) *bpf.AgentObjects {
	ret := &bpf.AgentObjects{}
	ret.AgentMaps = bpf.AgentMaps(legacy.AgentLagacyKernel310Maps)
	ret.AgentPrograms = bpf.AgentPrograms(legacy.AgentLagacyKernel310Programs)
	return ret
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
		if strings.HasPrefix(name, "tracepoint__syscalls") || strings.HasPrefix(name, "tracepoint__sched") || strings.HasPrefix(name, "kprobe__nf") {
			// if strings.HasPrefix(name, "tracepoint__syscalls") {
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
	Name:        "test",
	Type:        ebpf.Kprobe,
	SectionName: "kprobe/sys_accept",
	Instructions: asm.Instructions{
		asm.LoadImm(asm.R0, 2, asm.DWord),
		asm.Return(),
	},
	License: "MIT",
}

func setAndValidateParameters(ctx context.Context, options *ac.AgentOptions) bool {
	var controlValues *ebpf.Map = bpf.GetMapFromObjs(bpf.Objs, "ControlValues")
	var enabledRemotePortMap *ebpf.Map = bpf.GetMapFromObjs(bpf.Objs, "EnabledRemotePortMap")
	var enabledRemoteIpMap *ebpf.Map = bpf.GetMapFromObjs(bpf.Objs, "EnabledRemoteIpMap")
	var enabledLocalPortMap *ebpf.Map = bpf.GetMapFromObjs(bpf.Objs, "EnabledLocalPortMap")
	var filterPidMap *ebpf.Map = bpf.GetMapFromObjs(bpf.Objs, "FilterPidMap")

	controlValues.Update(bpf.AgentControlValueIndexTKSideFilter, int64(options.TraceSide), ebpf.UpdateAny)

	// if targetPid := viper.GetInt64(common.FilterPidVarName); targetPid > 0 {
	// 	common.AgentLog.Infoln("filter for pid: ", targetPid)
	// 	controlValues.Update(bpf.AgentControlValueIndexTKTargetTGIDIndex, targetPid, ebpf.UpdateAny)
	// }
	targetPids := viper.GetStringSlice(common.FilterPidVarName)
	if len(targetPids) > 0 {
		common.AgentLog.Infoln("filter for remote pids: ", targetPids)
		one := int64(1)
		controlValues.Update(bpf.AgentControlValueIndexTKEnableFilterByPid, one, ebpf.UpdateAny)
		for _, each := range targetPids {
			pidInt, err := strconv.Atoi(each)
			if err != nil {
				common.AgentLog.Errorf("Invalid pid : %s\n", each)
				return false
			}
			err = filterPidMap.Update(uint32(pidInt), int8(one), ebpf.UpdateAny)
			if err != nil {
				common.AgentLog.Errorf("Failed update  FilterPidMap: %s\n", err)
			}
		}
	}

	if options.FilterComm != "" {
		one := int64(1)
		controlValues.Update(bpf.AgentControlValueIndexTKEnableFilterByPid, one, ebpf.UpdateAny)

		common.AgentLog.Infoln("filter for comm:", options.FilterComm)
		processes, err := process.Processes()
		if err != nil {
			common.AgentLog.Errorf("Failed to get all processes: %s\n", err)
			return false
		}
		var matchedPids []int32
		for _, proc := range processes {
			if isProcNameMacthed(proc, options.FilterComm) {
				matchedPids = append(matchedPids, proc.Pid)
			} else {
				pn, _ := proc.Exe()
				common.AgentLog.Debugf("Not matched: %s %s\n", pn, options.FilterComm)
			}
		}

		common.AgentLog.Infof("Matched pids by command name: %v\n", matchedPids)

		for _, matchedPid := range matchedPids {
			err = filterPidMap.Update(uint32(matchedPid), int8(one), ebpf.UpdateAny)
			if err != nil {
				common.AgentLog.Errorf("Failed update  FilterPidMap: %s\n", err)
			}
		}
		options.ProcessExecEventChannel = make(chan *bpf.AgentProcessExecEvent, 10)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case execEvent := <-options.ProcessExecEventChannel:
					proc, err := process.NewProcess(execEvent.Pid)

					if err == nil && isProcNameMacthed(proc, options.FilterComm) {
						err = filterPidMap.Update(uint32(execEvent.Pid), int8(one), ebpf.UpdateAny)
						if err != nil {
							common.AgentLog.Errorf("Failed update  FilterPidMap: %s\n", err)
						}
					}
				}
			}
		}()
	}

	if options.FilterByContainer() && !options.Kv.SupportCapability(compatible.SupportFilterByContainer) {
		common.AgentLog.Warnf("current kernel version 3.10 doesn't support filter by container id/name/podname etc.")
	} else if options.FilterByContainer() {
		cc, filterResult, err := applyContainerFilter(ctx, options)
		if err == nil {
			options.Cc = cc
			writeFilterNsIdsToMap(filterResult, bpf.Objs)
			one := int64(1)
			controlValues.Update(bpf.AgentControlValueIndexTKEnableFilterByPid, one, ebpf.UpdateAny)
		}
	}

	remotePorts := viper.GetStringSlice(common.RemotePortsVarName)
	oneKey := uint16(1)
	zeroValue := uint8(0)
	if len(remotePorts) > 0 {
		common.AgentLog.Infoln("filter for remote ports: ", remotePorts)
		err := enabledRemotePortMap.Update(oneKey, zeroValue, ebpf.UpdateAny)
		if err != nil {
			common.AgentLog.Errorln("Update EnabledRemotePortMap failed: ", err)
		}
		for _, each := range remotePorts {
			portInt, err := strconv.Atoi(each)
			if err != nil || portInt <= 0 {
				common.AgentLog.Errorf("Invalid remote port : %s\n", each)
				return false
			}
			portNumber := uint16(portInt)
			err = enabledRemotePortMap.Update(portNumber, zeroValue, ebpf.UpdateAny)
			if err != nil {
				common.AgentLog.Errorln("Update EnabledRemotePortMap failed: ", err)
			}
		}
	}

	remoteIps := viper.GetStringSlice(common.RemoteIpsVarName)
	if len(remoteIps) > 0 {
		common.AgentLog.Infoln("filter for remote ips: ", remoteIps)
		oneKeyU32 := bpf.AgentIn6Addr{}
		oneKeyU32.In6U.U6Addr8[0] = 1
		err := enabledRemoteIpMap.Update(&oneKeyU32, &zeroValue, ebpf.UpdateAny)
		if err != nil {
			common.AgentLog.Errorln("Update EnabledRemoteIpv4Map failed: ", err)
		}
		for _, each := range remoteIps {
			ipBytes := common.NetIPToBytes(net.ParseIP(each), false)
			common.AgentLog.Debugln("Update EnabledRemoteIpv4Map, key: ", ipBytes, common.BytesToNetIP(ipBytes, false))
			key := bpf.AgentIn6Addr{}
			for i := range ipBytes {
				key.In6U.U6Addr8[i] = ipBytes[i]
			}
			err = enabledRemoteIpMap.Update(&key, &zeroValue, ebpf.UpdateAny)
			if err != nil {
				common.AgentLog.Errorln("Update EnabledRemoteIpv4Map failed: ", err)
			}
		}
	}

	localPorts := viper.GetStringSlice(common.LocalPortsVarName)
	if len(localPorts) > 0 {
		common.AgentLog.Infoln("filter for local ports: ", localPorts)
		err := enabledLocalPortMap.Update(oneKey, uint8(oneKey), ebpf.UpdateAny)
		if err != nil {
			common.AgentLog.Errorln("Update EnabledLocalPortMap failed: ", err)
		}
		for _, each := range localPorts {
			portInt, err := strconv.Atoi(each)
			if err != nil || portInt <= 0 {
				common.AgentLog.Errorf("Invalid local port : %s\n", each)
				return false
			}
			portNumber := uint16(portInt)
			err = enabledLocalPortMap.Update(portNumber, zeroValue, ebpf.UpdateAny)
			if err != nil {
				common.AgentLog.Errorln("Update EnabledLocalPortMap failed: ", err)
			}
		}
	}

	return true
}

func isProcNameMacthed(proc *process.Process, filterComm string) bool {
	procName, _ := proc.Name()
	if procName == filterComm {
		return true
	}
	if strings.Contains(procName, "/"+filterComm) {
		return true
	}
	return false
}

func attachBpfProgs(ifName string, kernelVersion *compatible.KernelVersion, options *ac.AgentOptions) *list.List {
	linkList := list.New()

	if kernelVersion.SupportCapability(compatible.SupportXDP) {
		l, err := bpf.AttachXdpWithSpecifiedIfName(options.IfName)
		if err != nil {
			common.AgentLog.Warnf("Attach XDP program failed, fallbacking...")
		} else {
			linkList.PushBack(l)
		}
	}

	if kernelVersion.SupportCapability(compatible.SupportRawTracepoint) {
		l, err := bpf.AttachRawTracepointTcpDestroySockEntry()
		if err != nil {
			common.AgentLog.Warnf("Attach TCP destroy raw tracepoint failed, fallbacking...")
		} else {
			linkList.PushBack(l)
		}
	}

	nonCriticalSteps := getNonCriticalSteps()
	for step, functions := range kernelVersion.InstrumentFunctions {
		_, isNonCriticalStep := nonCriticalSteps[step]
		if options.PerformanceMode && isNonCriticalStep {
			continue
		}
		for idx, function := range functions {
			var err error
			var l link.Link
			if function.IsKprobe() {
				l, err = bpf.Kprobe(function.GetKprobeName(), bpf.GetProgramFromObjs(bpf.Objs, function.BPFGoProgName))
			} else if function.IsTracepoint() {
				l, err = bpf.Tracepoint(function.GetTracepointGroupName(), function.GetTracepointName(),
					bpf.GetProgramFromObjs(bpf.Objs, function.BPFGoProgName))
			} else if function.IsKRetprobe() {
				l, err = bpf.Kretprobe(function.GetKprobeName(), bpf.GetProgramFromObjs(bpf.Objs, function.BPFGoProgName))
			} else {
				panic(fmt.Sprintf("invalid program type: %v", function))
			}
			if err != nil {
				if idx == len(functions)-1 {
					if isNonCriticalStep {
						common.AgentLog.Debugf("Attach failed: %v, functions: %v skip it because it's a non-criticalstep", err, functions)
					} else {
						common.AgentLog.Fatalf("Attach failed: %v, functions: %v", err, functions)
					}
				} else {
					common.AgentLog.Debugf("Attach failed but has fallback: %v, functions: %v", err, functions)
				}
			} else {
				linkList.PushBack(l)
				break
			}
		}
	}

	linkList.PushBack(bpf.AttachSyscallAcceptEntry())
	linkList.PushBack(bpf.AttachSyscallAcceptExit())

	linkList.PushBack(bpf.AttachSyscallSockAllocExit())

	linkList.PushBack(bpf.AttachSyscallConnectEntry())
	linkList.PushBack(bpf.AttachSyscallConnectExit())

	linkList.PushBack(bpf.AttachSyscallCloseEntry())
	linkList.PushBack(bpf.AttachSyscallCloseExit())

	linkList.PushBack(bpf.AttachSyscallWriteEntry())
	linkList.PushBack(bpf.AttachSyscallWriteExit())

	linkList.PushBack(bpf.AttachSyscallSendMsgEntry())
	linkList.PushBack(bpf.AttachSyscallSendMsgExit())

	linkList.PushBack(bpf.AttachSyscallRecvMsgEntry())
	linkList.PushBack(bpf.AttachSyscallRecvMsgExit())

	linkList.PushBack(bpf.AttachSyscallWritevEntry())
	linkList.PushBack(bpf.AttachSyscallWritevExit())

	linkList.PushBack(bpf.AttachSyscallSendtoEntry())
	linkList.PushBack(bpf.AttachSyscallSendtoExit())

	linkList.PushBack(bpf.AttachSyscallReadEntry())
	linkList.PushBack(bpf.AttachSyscallReadExit())

	linkList.PushBack(bpf.AttachSyscallReadvEntry())
	linkList.PushBack(bpf.AttachSyscallReadvExit())

	linkList.PushBack(bpf.AttachSyscallRecvfromEntry())
	linkList.PushBack(bpf.AttachSyscallRecvfromExit())

	linkList.PushBack(bpf.AttachKProbeSecuritySocketRecvmsgEntry())
	linkList.PushBack(bpf.AttachKProbeSecuritySocketSendmsgEntry())

	return linkList
}

func attachOpenSslUprobes(links *list.List, options *ac.AgentOptions, kernelVersion *compatible.KernelVersion, objs any) {
	if attachOpensslToSpecificProcess() {
		sslUprobeLinks, err := uprobe.AttachSslUprobe(int(viper.GetInt64(common.FilterPidVarName)))
		if err == nil {
			for _, l := range sslUprobeLinks {
				links.PushBack(l)
			}
		} else {
			common.AgentLog.Infof("Attach OpenSsl uprobes failed: %+v for pid: %d", err, viper.GetInt64(common.FilterPidVarName))
		}

	} else {
		pids, err := common.GetAllPids()
		loadGoTlsErr := uprobe.LoadGoTlsUprobe()
		if loadGoTlsErr != nil {
			common.UprobeLog.Debugf("Load GoTls Probe failed: %+v", loadGoTlsErr)
		}
		if err == nil {
			for _, pid := range pids {
				uprobeLinks, err := uprobe.AttachSslUprobe(int(pid))
				if err == nil && len(uprobeLinks) > 0 {
					for _, l := range uprobeLinks {
						links.PushBack(l)
					}
					common.UprobeLog.Infof("Attach OpenSsl uprobes success for pid: %d", pid)
				} else if err != nil {
					common.UprobeLog.Infof("Attach OpenSsl uprobes failed: %+v for pid: %d", err, pid)
				} else if len(uprobeLinks) == 0 {
					common.UprobeLog.Infof("Attach OpenSsl uprobes success for pid: %d use previous libssl path", pid)
				}
				if loadGoTlsErr == nil {
					gotlsUprobeLinks, err := uprobe.AttachGoTlsProbes(int(pid))

					if err == nil && len(gotlsUprobeLinks) > 0 {
						for _, l := range gotlsUprobeLinks {
							links.PushBack(l)
						}
						common.UprobeLog.Infof("Attach GoTls uprobes success for pid: %d", pid)
					} else if err != nil {
						common.UprobeLog.Infof("Attach GoTls uprobes failed: %+v for pid: %d", err, pid)
					} else {
						common.UprobeLog.Infof("Attach GoTls uprobes failed: %+v for pid: %d links is empty %v", err, pid, gotlsUprobeLinks)
					}
				}
			}
		} else {
			common.UprobeLog.Warnf("get all pid failed: %v", err)
		}
		attachSchedProgs(links)
		uprobeSchedExecEvent := uprobe.StartHandleSchedExecEvent()
		execEventChannels := []chan *bpf.AgentProcessExecEvent{uprobeSchedExecEvent}
		if options.ProcessExecEventChannel != nil {
			execEventChannels = append(execEventChannels, options.ProcessExecEventChannel)
		}
		bpf.PullProcessExecEvents(options.Ctx, execEventChannels)
	}
}

func attachOpensslToSpecificProcess() bool {
	return viper.GetInt64(common.FilterPidVarName) > 0
}

func attachSchedProgs(links *list.List) {
	link, err := link.Tracepoint("sched", "sched_process_exec", bpf.GetProgramFromObjs(bpf.Objs, "TracepointSchedSchedProcessExec"), nil)
	if err != nil {
		common.AgentLog.Warnf("Attach tracepoint/sched/sched_process_exec error: %v", err)
	} else {
		links.PushBack(link)
	}
}

func attachNfFunctions(links *list.List) {
	l, err := link.Kprobe("nf_nat_manip_pkt", bpf.GetProgramFromObjs(bpf.Objs, "KprobeNfNatManipPkt"), nil)
	if err != nil {
		common.AgentLog.Debugf("Attahc kprobe/nf_nat_manip_pkt failed: %v", err)
	} else {
		links.PushBack(l)
	}
	l, err = link.Kprobe("nf_nat_packet", bpf.GetProgramFromObjs(bpf.Objs, "KprobeNfNatPacket"), nil)
	if err != nil {
		common.AgentLog.Debugf("Attahc kprobe/nf_nat_packet failed: %v", err)
	} else {
		links.PushBack(l)
	}
}

func getNonCriticalSteps() map[bpf.AgentStepT]bool {
	return map[bpf.AgentStepT]bool{
		bpf.AgentStepTIP_OUT:    true,
		bpf.AgentStepTQDISC_OUT: true,
		bpf.AgentStepTIP_IN:     true,
	}
}
