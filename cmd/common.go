package cmd

import (
	"kyanos/agent"
	"kyanos/common"

	"github.com/sevlyar/go-daemon"
	"github.com/spf13/viper"
)

func startAgent(options agent.AgentOptions) {

	initLog()
	logger.Println("running kyanos ...")
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
			logger.Println("kyanos started!")
			return
		}
		defer cntxt.Release()
		logger.Println("----------------------")
		logger.Println("kyanos started!")
		agent.SetupAgent(options)
	} else {
		initLog()
		agent.SetupAgent(options)
	}
}
