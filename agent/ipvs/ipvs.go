package ipvs

import (
	"context"
	"fmt"

	"kyanos/common"
)

// IPVSAgent 是 IPVS 追踪的主入口
type IPVSAgent struct {
	tracker *IPVSTracker
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewIPVSAgent 创建新的 IPVS Agent
func NewIPVSAgent() *IPVSAgent {
	ctx, cancel := context.WithCancel(context.Background())
	return &IPVSAgent{
		tracker: NewIPVSTracker(),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start 启动 IPVS Agent
func (a *IPVSAgent) Start(perfPageCount int) error {
	common.AgentLog.Info("Starting IPVS Agent...")

	// 加载 BPF 程序
	if err := a.tracker.Load(); err != nil {
		return fmt.Errorf("failed to load IPVS BPF: %w", err)
	}

	// 附加探针
	if err := a.tracker.Attach(); err != nil {
		return fmt.Errorf("failed to attach IPVS probes: %w", err)
	}

	// 启动事件读取器
	if err := a.tracker.StartReader(perfPageCount); err != nil {
		return fmt.Errorf("failed to start IPVS reader: %w", err)
	}

	common.AgentLog.Info("IPVS Agent started successfully")
	return nil
}

// GetChainChannel 返回调用链通道
func (a *IPVSAgent) GetChainChannel() <-chan *IPVSChain {
	return a.tracker.GetChainChannel()
}

// Stop 停止 IPVS Agent
func (a *IPVSAgent) Stop() {
	common.AgentLog.Info("Stopping IPVS Agent...")
	a.cancel()
	a.tracker.Close()
}
