package bpf

import (
	"reflect"
)

var ProtocolNamesMap = map[AgentTrafficProtocolT]string{
	AgentTrafficProtocolTKProtocolHTTP:     "HTTP",
	AgentTrafficProtocolTKProtocolRedis:    "Redis",
	AgentTrafficProtocolTKProtocolMySQL:    "MySQL",
	AgentTrafficProtocolTKProtocolRocketMQ: "RocketMQ",
	AgentTrafficProtocolTKProtocolKafka:    "Kafka",
}

var StepCNNames [AgentStepTEnd + 1]string = [AgentStepTEnd + 1]string{"Start", "SSLWrite", "System Call(Out)", "TCP Layer(Out)", "IP Layer(Out)", "QDISC", "DEV Layer(Out)", "NIC(Out)", "NIC(In)", "DEV Layer(In)", "IP Layer(In)", "TCP Layer(In)", "User Data Copy", "System Call(In)", "SSLRead", "End"}

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
