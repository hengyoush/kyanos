package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"kyanos/common"
	"os"
	"unsafe"

	"github.com/cilium/ebpf/perf"
)

func PullProcessExitEvents(ctx context.Context, channels []chan *AgentProcessExitEvent) {
	pageSize := os.Getpagesize()
	perCPUBuffer := pageSize * 4
	eventSize := int(unsafe.Sizeof(AgentProcessExitEvent{}))
	if eventSize >= perCPUBuffer {
		perCPUBuffer = perCPUBuffer * (1 + (eventSize / perCPUBuffer))
	}
	reader, err := perf.NewReader(GetMapByObjs("ProcExitEvents", Objs), perCPUBuffer)
	if err == nil {
		go func(*perf.Reader) {
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
						common.BPFLog.Debug("[dataReader] Received signal, exiting..")
						return
					}
					common.BPFLog.Debugf("[dataReader] reading from reader: %s\n", err)
					continue
				}

				if evt, err := parseExitEvent(record.RawSample); err != nil {
					common.AgentLog.Errorf("[dataReader] handleKernEvt err: %s\n", err)
					continue
				} else {
					for _, ch := range channels {
						ch <- evt
					}
				}
			}
		}(reader)
	}
}

func parseExitEvent(rawSample []byte) (*AgentProcessExitEvent, error) {
	event := AgentProcessExitEvent{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}
	return &event, nil
}
