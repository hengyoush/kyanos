package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync/atomic"

	"kyanos/common"

	"github.com/cilium/ebpf/perf"
)

var (
	IpvsEventLostCnt atomic.Uint64
)

// IpvsIpvsEventT IPVS 事件结构体（与 BPF 程序中的 ipvs_event_t 对应）
type IpvsIpvsEventT struct {
	TimestampNs uint64
	LatencyNs   uint64
	ConnPtr     uint64
	SkbPtr      uint64
	Pid         uint32
	EventType   uint8
	Protocol    uint8
	ConnFlags   uint16
	ClientIp    uint32
	ClientPort  uint16
	Vip         uint32
	Vport       uint16
	RealIp      uint32
	RealPort    uint16
	Comm        [16]byte
}

// IpvsEventHook IPVS 事件钩子函数类型
type IpvsEventHook func(evt *IpvsIpvsEventT)

// PullIpvsEvents 从 perf buffer 拉取 IPVS 事件
func PullIpvsEvents(ctx context.Context, ipvsObjs *IpvsObjects, channel chan *IpvsIpvsEventT, perfCPUBufferPageNum int, hook IpvsEventHook) error {
	if ipvsObjs == nil {
		return errors.New("ipvs objects is nil")
	}

	reader, err := perf.NewReader(ipvsObjs.IpvsEvents, perfCPUBufferPageNum*4096)
	if err != nil {
		common.BPFLog.Warningf("[bpf] set up IPVS perf reader failed: %s\n", err)
		return err
	}

	go func() {
		defer reader.Close()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					common.BPFLog.Debug("[ipvsReader] Received signal, exiting..")
					return
				}
				common.BPFLog.Debugf("[ipvsReader] reading from reader: %s\n", err)
				continue
			}

			if record.LostSamples > 0 {
				IpvsEventLostCnt.Add(record.LostSamples)
				common.BPFLog.Warningf("[ipvsReader] lost %d IPVS events\n", record.LostSamples)
				continue
			}

			evt, err := ParseIpvsEvent(record.RawSample)
			if err != nil {
				common.AgentLog.Errorf("[ipvsReader] parse IPVS event err: %s\n", err)
				continue
			}

			if hook != nil {
				hook(evt)
			}

			select {
			case channel <- evt:
			default:
				common.BPFLog.Debug("[ipvsReader] channel full, dropping event")
			}
		}
	}()

	return nil
}

// ParseIpvsEvent 解析 IPVS 事件
func ParseIpvsEvent(rawSample []byte) (*IpvsIpvsEventT, error) {
	var event IpvsIpvsEventT
	err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event)
	if err != nil {
		return nil, err
	}
	return &event, nil
}
