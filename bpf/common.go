package bpf

var ProtocolNamesMap = map[AgentTrafficProtocolT]string{
	AgentTrafficProtocolTKProtocolHTTP:  "HTTP",
	AgentTrafficProtocolTKProtocolRedis: "Redis",
	AgentTrafficProtocolTKProtocolMySQL: "MySQL",
}

var StepCNNames [AgentStepTEnd + 1]string = [AgentStepTEnd + 1]string{"开始", "系统调用(出)", "TCP层(出)", "IP层(出)", "QDISC", "DEV层(出)", "网卡(出)", "网卡(进)", "DEV层(进)", "IP层(进)", "TCP层(进)", "用户拷贝", "系统调用(进)", "结束"}
