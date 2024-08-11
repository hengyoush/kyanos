package common

import (
	"eapm-ebpf/bpf"

	"github.com/jefurry/logrus"
)

var Log *logrus.Logger = logrus.New()

var CollectorAddrVarName string = "collector-addr"
var LocalModeVarName string = "local-mode"
var ConsoleOutputVarName string = "console-output"
var VerboseVarName string = "verbose"
var DaemonVarName string = "daemon"
var LogDirVarName string = "log-dir"
var LaunchEpochTime uint64

var StepCNNames [bpf.AgentStepTEnd + 1]string = [bpf.AgentStepTEnd + 1]string{"开始", "系统调用(出)", "TCP层(出)", "IP层(出)", "QDISC", "DEV层(出)", "网卡(出)", "网卡(进)", "DEV层(进)", "IP层(进)", "TCP层(进)", "用户拷贝", "系统调用(进)", "结束"}
