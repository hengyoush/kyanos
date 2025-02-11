package nats

import (
	"kyanos/agent/protocol"
)

var _ protocol.ProtocolStreamParser = &NatsStreamParser{}

type NatsStreamParser struct {
}

var _ protocol.ParsedMessage = &NatsMessage{}

type NatsMessage struct {
	protocol.FrameBase
	ProtocolCode ProtocolCode
	Subject      string
	isReq        bool
	Buf          []byte
}

type NatsProtocolParser interface {
	Parse(payload []byte, messageType protocol.MessageType) (*NatsMessage, int)
	CheckBoundary(stream string, pos int) bool
}

type Info struct {
	NatsMessage
	ServerID    string `json:"server_id"`
	ServerName  string `json:"server_name"`
	Version     string `json:"version"`
	GoVersion   string `json:"go"`
	Host        string `json:"host"`
	Port        uint16 `json:"port"`
	MaxPayload  int    `json:"max_payload"`
	TLSRequired bool   `json:"tls_required,omitempty"`
}

type Connect struct {
	NatsMessage
	Verbose     bool   `json:"verbose"`
	Pedantic    bool   `json:"pedantic"`
	TLSRequired bool   `json:"tls_required"`
	Name        string `json:"name,omitempty"`
	Version     string `json:"version"`
}

type Pub struct {
	NatsMessage
	Subject     string `json:"subject"`
	ReplyTo     string `json:"reply_to,omitempty"`
	PayloadSize int    `json:"payload_size"`
	Payload     []byte `json:"payload"`
}

type Hpub struct {
	NatsMessage
	Subject       string              `json:"subject"`
	ReplyTo       string              `json:"reply_to,omitempty"`
	PayloadSize   int                 `json:"payload_size"`
	HeaderSize    int                 `json:"header_size"`
	HeaderVersion string              `json:"header_version"`
	Headers       map[string][]string `json:"headers"`
	Payload       []byte              `json:"payload"`
}

type Sub struct {
	NatsMessage
	Subject    string `json:"subject"`
	QueueGroup string `json:"queue_group,omitempty"`
	Sid        string `json:"sid"`
}

type Unsub struct {
	NatsMessage
	Sid     string `json:"sid"`
	MaxMsgs int    `json:"max_msgs,omitempty"`
}

type Msg struct {
	NatsMessage
	Subject     string `json:"subject"`
	Sid         string `json:"sid"`
	ReplyTo     string `json:"reply_to,omitempty"`
	PayloadSize int    `json:"payload_size"`
	Payload     []byte `json:"payload"`
}

type Hmsg struct {
	NatsMessage
	Subject       string              `json:"subject"`
	Sid           string              `json:"sid"`
	ReplyTo       string              `json:"reply_to,omitempty"`
	HeaderSize    int                 `json:"header_size"`
	PayloadSize   int                 `json:"payload_size"`
	HeaderVersion string              `json:"header_version"`
	Headers       map[string][]string `json:"headers"`
	Payload       []byte              `json:"payload"`
}

type Ping struct {
	NatsMessage
}

type Pong struct {
	NatsMessage
}

type Ok struct {
	NatsMessage
}

type Err struct {
	NatsMessage
	ErrorMessage string `json:"error_message"`
}
