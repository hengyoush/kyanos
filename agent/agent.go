package agent

import (
	"context"
	"kyanos/agent/analysis"
	anc "kyanos/agent/analysis/common"
	ac "kyanos/agent/common"
	"kyanos/agent/compatible"
	"kyanos/agent/conn"
	"kyanos/agent/protocol"
	"kyanos/agent/render/stat"
	"kyanos/agent/render/watch"
	"kyanos/bpf"
	"kyanos/bpf/loader"
	"kyanos/common"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

func SetupAgent(options ac.AgentOptions) {
	options = ac.ValidateAndRepairOptions(options)
	common.LaunchEpochTime = GetMachineStartTimeNano()
	stopper := options.Stopper
	connManager := conn.InitConnManager()

	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, stopFunc := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	options.Ctx = ctx

	defer stopFunc()

	if options.ConnManagerInitHook != nil {
		options.ConnManagerInitHook(connManager)
	}
	statRecorder := analysis.InitStatRecorder()

	var recordsChannel chan *anc.AnnotatedRecord = nil
	recordsChannel = make(chan *anc.AnnotatedRecord, 1000)

	pm := conn.InitProcessorManager(options.ProcessorsNum, connManager, options.MessageFilter, options.LatencyFilter, options.SizeFilter, options.TraceSide)
	conn.RecordFunc = func(r protocol.Record, c *conn.Connection4) error {
		return statRecorder.ReceiveRecord(r, c, recordsChannel)
	}
	conn.OnCloseRecordFunc = func(c *conn.Connection4) error {
		statRecorder.RemoveRecord(c.TgidFd)
		return nil
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		common.AgentLog.Warn("Remove memlock:", err)
	}

	kernelVersion := compatible.GetCurrentKernelVersion()
	options.Kv = &kernelVersion
	var err error
	bf, err := loader.LoadBPF(options)
	if err != nil {
		if bf != nil {
			bf.Close()
		}
		return
	}
	defer bf.Close()
	err = bpf.PullSyscallDataEvents(ctx, pm.GetSyscallEventsChannels(), 2048, options.CustomSyscallEventHook)
	if err != nil {
		return
	}
	err = bpf.PullSslDataEvents(ctx, pm.GetSslEventsChannels(), 512, options.CustomSslEventHook)
	if err != nil {
		return
	}
	err = bpf.PullConnDataEvents(ctx, pm.GetConnEventsChannels(), 4, options.CustomConnEventHook)
	if err != nil {
		return
	}
	err = bpf.PullKernEvents(ctx, pm.GetKernEventsChannels(), 32, options.CustomKernEventHook)
	if err != nil {
		return
	}

	stop := false
	go func() {
		<-stopper
		// ac.SendStopSignal()
		common.AgentLog.Debugln("stop!")
		pm.StopAll()
		stop = true
	}()

	common.AgentLog.Info("Waiting for events..")

	if options.InitCompletedHook != nil {
		options.InitCompletedHook()
	}

	if options.AnalysisEnable {
		resultChannel := make(chan []*analysis.ConnStat, 1000)
		renderStopper := make(chan int)
		analyzer := analysis.CreateAnalyzer(recordsChannel, &options.AnalysisOptions, resultChannel, renderStopper, options.Ctx)
		go analyzer.Run()

		stat.StartStatRender(ctx, resultChannel, options.AnalysisOptions)
		// render := render.CreateRender(resultChannel, renderStopper, analyzer.AnalysisOptions)
		// go render.Run()
		// for !stop {
		// 	time.Sleep(time.Second * 1)
		// }
	} else {
		watch.RunWatchRender(ctx, recordsChannel, options.WatchOptions)
	}
	common.AgentLog.Infoln("Kyanos Stopped: ", stop)

	return
}
