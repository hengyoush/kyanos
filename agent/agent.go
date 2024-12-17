package agent

import (
	"context"
	"kyanos/agent/analysis"
	anc "kyanos/agent/analysis/common"
	ac "kyanos/agent/common"
	"kyanos/agent/compatible"
	"kyanos/agent/conn"
	"kyanos/agent/protocol"
	loader_render "kyanos/agent/render/loader"
	"kyanos/agent/render/stat"
	"kyanos/agent/render/watch"
	"kyanos/bpf"
	"kyanos/bpf/loader"
	"kyanos/common"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	gops "github.com/google/gops/agent"
)

func SetupAgent(options ac.AgentOptions) {
	if enabled, err := common.IsEnableBPF(); err == nil && !enabled {
		common.AgentLog.Error("BPF is not enabled in your kernel. This might be because your kernel version is too old. " +
			"Please check the requirements for Kyanos at https://kyanos.io/quickstart.html#installation-requirements.")
		return
	}

	if os.Geteuid() != 0 {
		common.AgentLog.Error("Kyanos requires root privileges to run. Please run kyanos with sudo.")
		return
	}

	if common.Is256ColorSupported() {
		common.AgentLog.Debugln("Terminal supports 256 colors")
	} else {
		common.AgentLog.Warnf("Your terminal does not support 256 colors, ui may display incorrectly")
	}

	// startGopsServer(options)
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

	wg := new(sync.WaitGroup)
	wg.Add(1)

	var _bf loader.BPF
	go func(_bf *loader.BPF) {
		options.LoadPorgressChannel <- "🍩 Kyanos starting..."
		kernelVersion := compatible.GetCurrentKernelVersion()
		options.Kv = &kernelVersion
		var err error
		{
			bf, err := loader.LoadBPF(&options)
			if err != nil {
				common.AgentLog.Error("Failed to load BPF programs: ", err)
				if bf != nil {
					bf.Close()
				}
				_bf.Err = err
				options.LoadPorgressChannel <- "❌ Kyanos start failed"
				options.LoadPorgressChannel <- "quit"
				return
			}
			_bf.Links = bf.Links
			_bf.Objs = bf.Objs
		}

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
		_bf.AttachProgs(&options)
		if !options.WatchOptions.DebugOutput {
			options.LoadPorgressChannel <- "🍹 All programs attached"
			options.LoadPorgressChannel <- "🍭 Waiting for events.."
			time.Sleep(500 * time.Millisecond)
			options.LoadPorgressChannel <- "quit"
		}
		defer wg.Done()
	}(&_bf)
	defer func() {
		_bf.Close()
	}()
	if !options.WatchOptions.DebugOutput {
		loader_render.Start(ctx, options)
		common.SetLogToStdout()
	} else {
		wg.Wait()
		common.AgentLog.Info("Waiting for events..")
	}
	if _bf.Err != nil {
		common.AgentLog.Error("Failed to load BPF: ", _bf.Err)
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

	if options.InitCompletedHook != nil {
		options.InitCompletedHook()
	}

	if options.AnalysisEnable {
		resultChannel := make(chan []*analysis.ConnStat, 1000)
		renderStopper := make(chan int)
		analyzer := analysis.CreateAnalyzer(recordsChannel, &options.AnalysisOptions, resultChannel, renderStopper, options.Ctx)
		go analyzer.Run()
		stat.StartStatRender(ctx, resultChannel, options.AnalysisOptions)
	} else {
		watch.RunWatchRender(ctx, recordsChannel, options.WatchOptions)
	}
	common.AgentLog.Infoln("Kyanos Stopped: ", stop)

	return
}

func startGopsServer(opts ac.AgentOptions) {
	if opts.WatchOptions.DebugOutput {
		if err := gops.Listen(gops.Options{}); err != nil {
			common.AgentLog.Fatalf("agent.Listen err: %v", err)
		} else {
			common.AgentLog.Info("gops server started")
		}
	}
}
