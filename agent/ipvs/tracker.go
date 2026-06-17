package ipvs

import (
	"context"
	"sync"
	"time"

	"kyanos/bpf"
	"kyanos/common"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// IPVSTracker 负责追踪 IPVS 事件
type IPVSTracker struct {
	objs       *bpf.IpvsObjects
	links      []link.Link
	reader     *perf.Reader
	chains     map[uint64]*IPVSChain // connPtr -> chain
	chainsMu   sync.RWMutex
	eventChan  chan *IPVSEvent
	chainChan  chan *IPVSChain
	ctx        context.Context
	cancel     context.CancelFunc
	cleanupTTL time.Duration
}

// NewIPVSTracker 创建新的 IPVS 追踪器
func NewIPVSTracker() *IPVSTracker {
	common.AgentLog.Info("[IPVS] Creating new IPVS tracker")
	ctx, cancel := context.WithCancel(context.Background())
	return &IPVSTracker{
		chains:     make(map[uint64]*IPVSChain),
		eventChan:  make(chan *IPVSEvent, 10000),
		chainChan:  make(chan *IPVSChain, 1000),
		ctx:        ctx,
		cancel:     cancel,
		cleanupTTL: 30 * time.Second,
	}
}

// Load 加载 IPVS BPF 程序
func (t *IPVSTracker) Load() error {
	common.AgentLog.Info("[IPVS] Loading IPVS BPF program...")
	spec, err := bpf.LoadIpvs()
	if err != nil {
		common.AgentLog.Errorf("[IPVS] Failed to load IPVS BPF spec: %v", err)
		return err
	}
	common.AgentLog.Info("[IPVS] IPVS BPF spec loaded successfully")

	t.objs = &bpf.IpvsObjects{}
	if err := spec.LoadAndAssign(t.objs, &ebpf.CollectionOptions{}); err != nil {
		common.AgentLog.Errorf("[IPVS] Failed to load and assign IPVS BPF objects: %v", err)
		return err
	}
	common.AgentLog.Info("[IPVS] IPVS BPF objects loaded and assigned successfully")

	return nil
}

// Attach 附加 kprobe/kretprobe
func (t *IPVSTracker) Attach() error {
	common.AgentLog.Info("[IPVS] ==========================================")
	common.AgentLog.Info("[IPVS] Starting to attach IPVS kprobes...")
	common.AgentLog.Info("[IPVS] ==========================================")

	probes := []struct {
		name    string
		prog    *ebpf.Program
		isRet   bool
	}{
		{"ip_vs_conn_new", t.objs.KprobeIpVsConnNew, false},
		{"ip_vs_conn_new", t.objs.KretprobeIpVsConnNew, true},
		{"ip_vs_conn_in_get", t.objs.KprobeIpVsConnInGet, false},
		{"ip_vs_conn_in_get", t.objs.KretprobeIpVsConnInGet, true},
		{"ip_vs_conn_out_get", t.objs.KprobeIpVsConnOutGet, false},
		{"ip_vs_conn_out_get", t.objs.KretprobeIpVsConnOutGet, true},
		{"ip_vs_schedule", t.objs.KprobeIpVsSchedule, false},
		{"ip_vs_schedule", t.objs.KretprobeIpVsSchedule, true},
		{"ip_vs_nat_xmit", t.objs.KprobeIpVsNatXmit, false},
		{"ip_vs_nat_xmit", t.objs.KretprobeIpVsNatXmit, true},
		{"ip_vs_dr_xmit", t.objs.KprobeIpVsDrXmit, false},
		{"ip_vs_dr_xmit", t.objs.KretprobeIpVsDrXmit, true},
		{"ip_vs_tunnel_xmit", t.objs.KprobeIpVsTunnelXmit, false},
		{"ip_vs_tunnel_xmit", t.objs.KretprobeIpVsTunnelXmit, true},
		{"ip_vs_conn_put", t.objs.KprobeIpVsConnPut, false},
		{"ip_vs_conn_put", t.objs.KretprobeIpVsConnPut, true},
	}

	successCount := 0
	failCount := 0
	for _, p := range probes {
		var l link.Link
		var err error
		probeType := "kprobe"
		if p.isRet {
			probeType = "kretprobe"
		}

		if p.isRet {
			l, err = link.Kretprobe(p.name, p.prog, nil)
		} else {
			l, err = link.Kprobe(p.name, p.prog, nil)
		}

		if err != nil {
			common.AgentLog.Warnf("[IPVS] FAILED to attach %s/%s: %v", probeType, p.name, err)
			failCount++
			continue
		}

		t.links = append(t.links, l)
		common.AgentLog.Infof("[IPVS] Successfully attached %s/%s", probeType, p.name)
		successCount++
	}

	common.AgentLog.Infof("[IPVS] Probe attachment summary: %d succeeded, %d failed, %d total", successCount, failCount, len(probes))

	if len(t.links) == 0 {
		common.AgentLog.Warn("[IPVS] No IPVS probes attached! IPVS module may not be loaded. Check: lsmod | grep ip_vs")
	}

	return nil
}

// StartReader 启动 perf 事件读取器
func (t *IPVSTracker) StartReader(pageCount int) error {
	common.AgentLog.Infof("[IPVS] Starting perf reader with page count: %d", pageCount)
	reader, err := perf.NewReader(t.objs.IpvsEvents, pageCount*4096)
	if err != nil {
		common.AgentLog.Errorf("[IPVS] Failed to create perf reader: %v", err)
		return err
	}
	t.reader = reader
	common.AgentLog.Info("[IPVS] Perf reader created successfully")

	go t.readEvents()
	go t.processEvents()
	go t.cleanupStaleChains()

	common.AgentLog.Info("[IPVS] Event processing goroutines started")
	return nil
}

// readEvents 从 perf buffer 读取事件
func (t *IPVSTracker) readEvents() {
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		record, err := t.reader.Read()
		if err != nil {
			if err == perf.ErrClosed {
				return
			}
			common.AgentLog.Warnf("Error reading perf event: %v", err)
			continue
		}

		if record.LostSamples > 0 {
			common.AgentLog.Warnf("Lost %d IPVS samples", record.LostSamples)
			continue
		}

		raw, err := bpf.ParseIpvsEvent(record.RawSample)
		if err != nil {
			common.AgentLog.Warnf("[IPVS] Error parsing IPVS event: %v", err)
			continue
		}

		event := ParseEvent(raw)
		common.AgentLog.Debugf("[IPVS] Received event: type=%s, connPtr=0x%x, vip=%s:%d, realIP=%s:%d",
			event.EventType.String(), event.ConnPtr, event.VIP.String(), event.VPort, event.RealIP.String(), event.RealPort)
		t.eventChan <- event
	}
}

// processEvents 处理事件并构建调用链
func (t *IPVSTracker) processEvents() {
	for {
		select {
		case <-t.ctx.Done():
			return
		case event := <-t.eventChan:
			t.handleEvent(event)
		}
	}
}

// handleEvent 处理单个事件
func (t *IPVSTracker) handleEvent(event *IPVSEvent) {
	if event.ConnPtr == 0 {
		return
	}

	t.chainsMu.Lock()
	defer t.chainsMu.Unlock()

	chain, exists := t.chains[event.ConnPtr]
	if !exists {
		chain = NewIPVSChain(event)
		t.chains[event.ConnPtr] = chain
	} else {
		chain.AddEvent(event)
	}

	// 如果调用链完整，发送到输出通道
	if chain.IsComplete() {
		common.AgentLog.Infof("[IPVS] Chain complete: VIP=%s:%d -> RealServer=%s:%d",
			chain.VIP.String(), chain.VPort, chain.RealIP.String(), chain.RealPort)
		
		// 无论 channel 是否满了，都要添加到全局缓存
		GetGlobalCache().Add(chain)
		
		select {
		case t.chainChan <- chain:
			// chain 成功发送到 channel
		default:
			common.AgentLog.Debug("[IPVS] Chain channel full, but already added to cache")
		}
		delete(t.chains, event.ConnPtr)
	}
}

// cleanupStaleChains 清理过期的调用链
func (t *IPVSTracker) cleanupStaleChains() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			t.chainsMu.Lock()
			now := time.Now()
			for connPtr, chain := range t.chains {
				if now.Sub(chain.StartTime) > t.cleanupTTL {
					// 发送不完整的调用链
					select {
					case t.chainChan <- chain:
					default:
					}
					delete(t.chains, connPtr)
				}
			}
			t.chainsMu.Unlock()
		}
	}
}

// GetChainChannel 返回调用链输出通道
func (t *IPVSTracker) GetChainChannel() <-chan *IPVSChain {
	return t.chainChan
}

// GetEventChannel 返回事件输出通道
func (t *IPVSTracker) GetEventChannel() <-chan *IPVSEvent {
	return t.eventChan
}

// Close 关闭追踪器
func (t *IPVSTracker) Close() {
	t.cancel()

	if t.reader != nil {
		t.reader.Close()
	}

	for _, l := range t.links {
		l.Close()
	}

	if t.objs != nil {
		t.objs.Close()
	}

	close(t.eventChan)
	close(t.chainChan)
}
