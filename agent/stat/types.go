package stat

import (
	"fmt"
	"kyanos/agent/conn"
	"kyanos/bpf"
	"net"
)

type Addr []byte

func (a *Addr) String() string {
	if len(*a) == 4 {
		return net.IP(*a).To4().String()
	} else if len(*a) == 8 {
		return net.IP(*a).To16().String()
	} else {
		panic("unknown addr type")
	}
}

type Port uint16

type ConnDesc struct {
	LocalPort  Port
	RemotePort Port
	RemoteAddr Addr
	LocalAddr  Addr
	Pid        uint32
	Protocol   bpf.AgentTrafficProtocolT
	Side       conn.SideEnum
	StreamId   int
}

func (c *ConnDesc) String() string {
	direct := "=>"
	if c.Side != conn.ClientSide {
		direct = "<="
	}
	return fmt.Sprintf("[pid=%d][protocol=%d] *%s:%d %s %s:%d", c.Pid, c.Protocol, c.LocalAddr.String(), c.LocalPort, direct, c.RemoteAddr.String(), c.RemotePort)
}

type ConnStatistics struct {
	ConnDesc
	Avg                 float32
	P99                 float32
	P999                float32
	Max                 float32
	BigResponseSamples  []*AnnotatedRecord
	SlowResponseSamples []*AnnotatedRecord
	RecentSamples       []*AnnotatedRecord
}
