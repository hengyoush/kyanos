package common

var CollectorAddrVarName string = "collector-addr"
var LocalModeVarName string = "local-mode"

// var VerboseVarName string = "verbose"
var DaemonVarName string = "daemon"
var LogDirVarName string = "log-dir"
var FilterPidVarName string = "pids"
var RemotePortsVarName string = "remote-ports"
var LocalPortsVarName string = "local-ports"
var RemoteIpsVarName string = "remote-ips"
var LaunchEpochTime uint64

var AF_INET uint16 = 2
var AF_INET6 uint16 = 10

var TCP_FLAGS_ACK = 1 << 4
var TCP_FLAGS_PSH = 1 << 3
var TCP_FLAGS_RST = 1 << 2
var TCP_FLAGS_SYN = 1 << 1

type SideEnum int8

const AllSide SideEnum = 0
const ServerSide SideEnum = 1
const ClientSide SideEnum = 2

func (s SideEnum) String() string {
	if s == ServerSide {
		return "server"
	} else if s == ClientSide {
		return "client"
	} else {
		return "all"
	}
}

type DirectEnum int

const DirectEgress DirectEnum = 0
const DirectIngress DirectEnum = 1
