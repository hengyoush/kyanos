package cmd

import (
	"kyanos/agent"
	"kyanos/agent/protocol"
	"kyanos/common"

	"github.com/sevlyar/go-daemon"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type ModeEnum int

var Mode ModeEnum

const (
	WatchMode ModeEnum = iota
	AnalysisMode
)

func startAgent(options agent.AgentOptions) {
	if Mode == AnalysisMode {
		options.AnalysisEnable = true
		analysisOptions, err := createAnalysisOptions()
		if err != nil {
			return
		}
		options.AnalysisOptions = analysisOptions
	}
	initLog()
	logger.Infoln("Kyanos starting...")
	if viper.GetBool(common.DaemonVarName) {
		cntxt := &daemon.Context{
			PidFileName: "./kyanos.pid",
			PidFilePerm: 0644,
			LogFileName: "./kyanos.log",
			LogFilePerm: 0640,
			WorkDir:     "./",
			// Umask:       027,
			Args: nil, // use current os args
		}
		d, err := cntxt.Reborn()
		if err != nil {
			logger.Fatal("Unable to run: ", err)
		}
		if d != nil {
			logger.Println("Kyanos started!")
			return
		}
		defer cntxt.Release()
		logger.Println("----------------------")
		logger.Println("Kyanos started!")
		agent.SetupAgent(options)
	} else {
		initLog()
		agent.SetupAgent(options)
	}
}

func initLatencyFilter(cmd *cobra.Command) protocol.LatencyFilter {
	latency, err := cmd.Flags().GetFloat64("latency")
	if err != nil {
		logger.Fatalf("invalid latency: %v\n", err)
	}
	latencyFilter := protocol.LatencyFilter{
		MinLatency: latency,
	}
	return latencyFilter
}

func initSizeFilter(cmd *cobra.Command) protocol.SizeFilter {
	reqSizeLimit, err := cmd.Flags().GetInt64("req-size")
	if err != nil {
		logger.Fatalf("invalid req-size: %v\n", err)
	}
	respSizeLimit, err := cmd.Flags().GetInt64("resp-size")
	if err != nil {
		logger.Fatalf("invalid resp-size: %v\n", err)
	}
	sizeFilter := protocol.SizeFilter{
		MinReqSize:  reqSizeLimit,
		MinRespSize: respSizeLimit,
	}
	return sizeFilter
}
