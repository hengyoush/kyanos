package metadata

import (
	"context"
	"kyanos/bpf"
	"kyanos/common"
	"sync"
	"time"

	"github.com/shirou/gopsutil/process"
)

var cleanupTimeout = 5 * time.Second

const defaultProcDir = "/proc"

type PIDInfo struct {
	PID       int
	NetNS     int64
	Timestamp time.Time
}

var (
	HostMntNs int64
	HostPidNs int64
	HostNetNs int64
	pidCache  = sync.Map{}
	deadPids  = sync.Map{}
	cacheLock sync.Mutex
)

func init() {
	HostPidNs = common.GetPidNamespaceFromPid(1)
	HostMntNs = common.GetMountNamespaceFromPid(1)
	HostNetNs = common.GetNetworkNamespaceFromPid(1)
	go func() {
		for range time.Tick(1 * time.Second) {
			cleanupDeadPIDs()
		}
	}()
}

func StartHandleSchedExecEvent(ch chan *bpf.AgentProcessExecEvent, ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case execEvent := <-ch:
				proc, err := process.NewProcess(execEvent.Pid)
				if err != nil {
					common.AgentLog.Infof("Failed to create process for PID %d: %v", execEvent.Pid, err)
					continue
				}
				startPID(int(proc.Pid), common.GetNetworkNamespaceFromPid(int(proc.Pid)))
			}
		}
	}()
}

func StartHandleSchedExitEvent(ch chan *bpf.AgentProcessExitEvent, ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case execEvent := <-ch:
				stopPID(int(execEvent.Pid))
			}
		}
	}()
}

func startPID(pid int, netns int64) {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	common.AgentLog.Infof("Start tracking PID %d, netns: %d", pid, netns)
	pidCache.Store(pid, PIDInfo{
		PID:       pid,
		NetNS:     netns,
		Timestamp: time.Now(),
	})
}

func stopPID(pid int) {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	common.AgentLog.Debugf("Stop tracking PID %d, netns: %d", pid)
	if info, exists := pidCache.Load(pid); exists {
		pidCache.Delete(pid)
		pidInfo := info.(PIDInfo)
		pidInfo.Timestamp = time.Now()
		deadPids.Store(pid, pidInfo)
	}
}

func cleanupDeadPIDs() {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	now := time.Now()
	deadPids.Range(func(key, value interface{}) bool {
		info := value.(PIDInfo)
		if now.Sub(info.Timestamp) > cleanupTimeout {
			deadPids.Delete(key)
		}
		return true
	})
}

func GetPidInfo(pid int) PIDInfo {
	if info, exists := pidCache.Load(pid); exists {
		return info.(PIDInfo)
	}
	// find from deadPids
	if info, exists := deadPids.Load(pid); exists {
		return info.(PIDInfo)
	}

	return PIDInfo{}
}
