package cmd

import (
	"fmt"
	"kyanos/agent"
	"kyanos/agent/protocol"
	"kyanos/common"
	"net"

	"github.com/jefurry/logrus"
	"github.com/sevlyar/go-daemon"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type ModeEnum int

var Mode ModeEnum
var SidePar string

const (
	WatchMode ModeEnum = iota
	AnalysisMode
)

func ParseSide(side string) (common.SideEnum, error) {
	switch side {
	case "all":
		return common.AllSide, nil
	case "server":
		return common.ServerSide, nil
	case "client":
		return common.ClientSide, nil
	default:
		logger.Errorf("invalid side: %s", side)
		return common.AllSide, fmt.Errorf("invalid side: %s", side)
	}
}

func startAgent(options agent.AgentOptions) {
	side, err := ParseSide(SidePar)
	if err != nil {
		return
	}
	options.TraceSide = side
	if Mode == AnalysisMode {
		options.AnalysisEnable = true
		analysisOptions, err := createAnalysisOptions()
		if err != nil {
			return
		}
		options.AnalysisOptions = analysisOptions
		options.Side = side
	}
	_, err = net.InterfaceByName(IfName)
	if err != nil {
		logger.Errorf("Start Kyanos failed: %v", err)
		return
	}
	options.IfName = IfName
	options.BTFFilePath = BTFFilePath
	options.BPFVerifyLogSize = BPFVerifyLogSize
	options.PerfEventBufferSizeForEvent = KernEvtPerfEventBufferSize
	options.PerfEventBufferSizeForData = DataEvtPerfEventBufferSize

	initLog()
	common.AgentLog.Infoln("Kyanos starting...")
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

func initLog() {
	if viper.GetBool("debug") {
		DefaultLogLevel = int32(logrus.DebugLevel)
	}
	if isValidLogLevel(DefaultLogLevel) {
		common.DefaultLog.SetLevel(logrus.Level(DefaultLogLevel))
	} else {
		common.DefaultLog.SetLevel(logrus.WarnLevel)
	}
	common.AgentLog.SetLevel(common.DefaultLog.Level)
	common.BPFEventLog.SetLevel(common.DefaultLog.Level)
	common.ConntrackLog.SetLevel(common.DefaultLog.Level)
	common.ProtocolParserLog.SetLevel(common.DefaultLog.Level)

	// override log level individually
	if isValidLogLevel(AgentLogLevel) {
		common.AgentLog.SetLevel(logrus.Level(AgentLogLevel))
	}
	if isValidLogLevel(BPFEventLogLevel) {
		common.BPFEventLog.SetLevel(logrus.Level(BPFEventLogLevel))
	}
	if isValidLogLevel(ConntrackLogLevel) {
		common.ConntrackLog.SetLevel(logrus.Level(ConntrackLogLevel))
	}
	if isValidLogLevel(ProtocolLogLevel) {
		common.ProtocolParserLog.SetLevel(logrus.Level(ProtocolLogLevel))
	}
}

func isValidLogLevel(level int32) bool {
	if level < int32(logrus.FatalLevel) || level > int32(logrus.DebugLevel) {
		return false
	}
	return true
}
