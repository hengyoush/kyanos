package bpf

import (
	"reflect"
)

var ProtocolNamesMap = map[AgentTrafficProtocolT]string{
	AgentTrafficProtocolTKProtocolHTTP:  "HTTP",
	AgentTrafficProtocolTKProtocolRedis: "Redis",
	AgentTrafficProtocolTKProtocolMySQL: "MySQL",
}

var StepCNNames [AgentStepTEnd + 1]string = [AgentStepTEnd + 1]string{"开始", "SSLWrite", "系统调用(出)", "TCP层(出)", "IP层(出)", "QDISC", "DEV层(出)", "网卡(出)", "网卡(进)", "DEV层(进)", "IP层(进)", "TCP层(进)", "用户拷贝", "系统调用(进)", "SSLRead", "结束"}

var XDPProgramName = "xdp_proxy"
var TcpDestroySocketProgName = "tcp_destroy_sock"

var SyscallExtraProgNames = []string{
	"security_socket_recvmsg_enter",
	"security_socket_sendmsg_enter",
	"sock_alloc_ret",
}
var GoProgName2CProgName map[string]string
var CProgName2GoProgName map[string]string

func ExtractEbpfTags(s interface{}) map[string]string {
	result := make(map[string]string)
	val := reflect.TypeOf(s)

	// Loop through the fields of the struct
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		tag := field.Tag.Get("ebpf")
		if tag != "" {
			result[field.Name] = tag
		}
	}
	return result
}

func init() {
	var p AgentPrograms
	GoProgName2CProgName = ExtractEbpfTags(p)
	CProgName2GoProgName = make(map[string]string)
	for k, v := range GoProgName2CProgName {
		CProgName2GoProgName[v] = k
	}
}
