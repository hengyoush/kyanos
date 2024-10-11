package common

import (
	"fmt"
	"net"
)

// type Addr []byte

// func (a *Addr) String() string {
// 	if len(*a) == 4 {
// 		return net.IP(*a).To4().String()
// 	} else if len(*a) == 8 {
// 		return net.IP(*a).To16().String()
// 	} else {
// 		panic("unknown addr type")
// 	}
// }

type Port uint16

type ConnDesc struct {
	LocalPort  Port
	RemotePort Port
	RemoteAddr net.IP
	LocalAddr  net.IP
	Pid        uint32
	Protocol   uint32
	Side       SideEnum
	StreamId   int
	IsSsl      bool
}

func (c *ConnDesc) Identity() string {
	localPortBytes := IntToBytes(uint16(c.LocalPort))
	remotePortBytes := IntToBytes(uint16(c.RemotePort))

	result := append(c.LocalAddr, localPortBytes...)
	result = append(result, append(c.RemoteAddr, remotePortBytes...)...)
	return string(result)
}

func (c *ConnDesc) String() string {
	direct := "=>"
	if c.Side != ClientSide {
		direct = "<="
	}
	return fmt.Sprintf("[pid=%d][protocol=%d] *%s:%d %s %s:%d", c.Pid, c.Protocol, c.LocalAddr.String(), c.LocalPort, direct, c.RemoteAddr.String(), c.RemotePort)
}

func (c *ConnDesc) SimpleString() string {
	direct := "=>"
	if c.Side != ClientSide {
		direct = "<="
	}
	return fmt.Sprintf("%s:%d %s %s:%d", c.LocalAddr.String(), c.LocalPort, direct, c.RemoteAddr.String(), c.RemotePort)
}
