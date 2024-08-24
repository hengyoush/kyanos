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
var FilterPidVarName string = "pid"
var RemotePortsVarName string = "remote-ports"
var LocalPortsVarName string = "local-ports"
var RemoteIpsVarName string = "remote-ips"
var LaunchEpochTime uint64

var AF_INET = 2
var AF_INET6 = 10

var TCP_FLAGS_ACK = 1 << 4
var TCP_FLAGS_PSH = 1 << 3
var TCP_FLAGS_RST = 1 << 2
var TCP_FLAGS_SYN = 1 << 1

var StepCNNames [bpf.AgentStepTEnd + 1]string = [bpf.AgentStepTEnd + 1]string{"开始", "系统调用(出)", "TCP层(出)", "IP层(出)", "QDISC", "DEV层(出)", "网卡(出)", "网卡(进)", "DEV层(进)", "IP层(进)", "TCP层(进)", "用户拷贝", "系统调用(进)", "结束"}
