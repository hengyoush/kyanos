package cmd

import (
	"eapm-ebpf/agent"
	"eapm-ebpf/common"

	"github.com/sevlyar/go-daemon"
	"github.com/spf13/viper"
)

func startAgent(options agent.AgentOptions) {

	initLog()
	logger.Println("run eAPM eBPF Agent ...")
	if viper.GetBool(common.DaemonVarName) {
		cntxt := &daemon.Context{
			PidFileName: "./eapm-ebpf.pid",
			PidFilePerm: 0644,
			LogFileName: "./eapm-ebpf.log",
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
			logger.Println("eAPM eBPF agent started!")
			return
		}
		defer cntxt.Release()
		logger.Println("----------------------")
		logger.Println("eAPM eBPF agent started!")
		agent.SetupAgent(options)
	} else {
		initLog()
		agent.SetupAgent(options)
	}
}
