package common

import "github.com/jefurry/logrus"

var Log *logrus.Logger = logrus.New()

var CollectorAddrVarName string = "collector-addr"
var LocalModeVarName string = "local-mode"
var ConsoleOutputVarName string = "console-output"
var VerboseVarName string = "verbose"
var DaemonVarName string = "daemon"
var LogDirVarName string = "log-dir"
var LaunchEpochTime uint64
