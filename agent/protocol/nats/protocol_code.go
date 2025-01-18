package nats

import (
	"errors"
	"fmt"
)

type ProtocolCode byte

const (
	INFO    ProtocolCode = iota // 0
	CONNECT                     // 1
	PUB                         // 2
	HPUB                        // 3
	SUB                         // 4
	UNSUB                       // 5
	MSG                         // 6
	HMSG                        // 7
	PING                        // 8
	PONG                        // 9
	OK                          // 10
	ERR                         // 11
	UNKNOWN
)

func ConvertToProtocolCode(op string) (ProtocolCode, error) {
	switch op {
	case "INFO":
		return INFO, nil
	case "CONNECT":
		return CONNECT, nil
	case "PUB":
		return PUB, nil
	case "HPUB":
		return HPUB, nil
	case "SUB":
		return SUB, nil
	case "UNSUB":
		return UNSUB, nil
	case "MSG":
		return MSG, nil
	case "HMSG":
		return HMSG, nil
	case "PING":
		return PING, nil
	case "PONG":
		return PONG, nil
	case "+OK":
		return OK, nil
	case "-ERR":
		return ERR, nil
	default:
		return UNKNOWN, errors.New("unknown protocol: " + op)
	}
}

func convertToProtocolCodeFromByte(flag byte) (ProtocolCode, error) {
	if flag >= byte(UNKNOWN) {
		return 0, errors.New("unknown protocol flag: " + fmt.Sprint(flag))
	}
	return ProtocolCode(flag), nil
}

func (op ProtocolCode) String() string {
	switch op {
	case INFO:
		return "INFO"
	case CONNECT:
		return "CONNECT"
	case PUB:
		return "PUB"
	case HPUB:
		return "HPUB"
	case SUB:
		return "SUB"
	case UNSUB:
		return "UNSUB"
	case MSG:
		return "MSG"
	case HMSG:
		return "HMSG"
	case PING:
		return "PING"
	case PONG:
		return "PONG"
	case OK:
		return "+OK"
	case ERR:
		return "-ERR"
	default:
		return "UNKNOWN"
	}
}
