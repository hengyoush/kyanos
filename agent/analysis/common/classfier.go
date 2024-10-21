package common

var ClassfierTypeNames = map[ClassfierType]string{
	None:             "none",
	Conn:             "conn",
	RemotePort:       "remote-port",
	LocalPort:        "local-port",
	RemoteIp:         "remote-ip",
	Protocol:         "protocol",
	HttpPath:         "http-path",
	RedisCommand:     "redis-command",
	ProtocolAdaptive: "protocol-adaptive",
	Default:          "default",
}

const (
	Default ClassfierType = iota
	None
	Conn
	RemotePort
	LocalPort
	RemoteIp
	Protocol

	// Http
	HttpPath

	// Redis
	RedisCommand

	ProtocolAdaptive
)

type ClassId string
