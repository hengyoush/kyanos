package cmd

import (
	"kyanos/agent"
	"kyanos/common"

	"github.com/sevlyar/go-daemon"
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
