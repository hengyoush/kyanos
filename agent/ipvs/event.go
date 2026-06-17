package ipvs

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"kyanos/bpf"
)

// EventType IPVS 事件类型
type EventType uint8

const (
	EventConnNew    EventType = 0 // 新建连接
	EventConnIn     EventType = 1 // 入站连接查找
	EventConnOut    EventType = 2 // 出站连接查找
	EventSchedule   EventType = 3 // 调度选择后端
	EventNatXmit    EventType = 4 // NAT 模式转发
	EventDrXmit     EventType = 5 // DR 模式转发
	EventTunnelXmit EventType = 6 // 隧道模式转发
	EventConnPut    EventType = 7 // 释放连接引用
)

// EventTypeName 返回事件类型名称
func (e EventType) String() string {
	names := []string{
		"CONN_NEW",
		"CONN_IN",
		"CONN_OUT",
		"SCHEDULE",
		"NAT_XMIT",
		"DR_XMIT",
		"TUNNEL_XMIT",
		"CONN_PUT",
	}
	if int(e) < len(names) {
		return names[e]
	}
	return fmt.Sprintf("UNKNOWN(%d)", e)
}

// IPVSEvent 表示一个 IPVS 事件
type IPVSEvent struct {
	TimestampNs uint64
	LatencyNs   uint64
	ConnPtr     uint64
	SkbPtr      uint64
	Pid         uint32
	EventType   EventType
	Protocol    uint8
	ConnFlags   uint16
	ClientIP    net.IP
	ClientPort  uint16
	VIP         net.IP
	VPort       uint16
	RealIP      net.IP
	RealPort    uint16
	Comm        string
}

// ParseEvent 从 BPF 事件解析 IPVS 事件
func ParseEvent(raw *bpf.IpvsIpvsEventT) *IPVSEvent {
	event := &IPVSEvent{
		TimestampNs: raw.TimestampNs,
		LatencyNs:   raw.LatencyNs,
		ConnPtr:     raw.ConnPtr,
		SkbPtr:      raw.SkbPtr,
		Pid:         raw.Pid,
		EventType:   EventType(raw.EventType),
		Protocol:    raw.Protocol,
		ConnFlags:   raw.ConnFlags,
		ClientIP:    uint32ToIP(raw.ClientIp),
		ClientPort:  ntohs(raw.ClientPort),
		VIP:         uint32ToIP(raw.Vip),
		VPort:       ntohs(raw.Vport),
		RealIP:      uint32ToIP(raw.RealIp),
		RealPort:    ntohs(raw.RealPort),
		Comm:        bytesToString(raw.Comm[:]),
	}
	return event
}

// FormatLatency 格式化延迟时间
func (e *IPVSEvent) FormatLatency() string {
	if e.LatencyNs < 1000 {
		return fmt.Sprintf("%dns", e.LatencyNs)
	} else if e.LatencyNs < 1000000 {
		return fmt.Sprintf("%.2fµs", float64(e.LatencyNs)/1000)
	} else {
		return fmt.Sprintf("%.2fms", float64(e.LatencyNs)/1000000)
	}
}

// ProtocolName 返回协议名称
func (e *IPVSEvent) ProtocolName() string {
	switch e.Protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO(%d)", e.Protocol)
	}
}

// ForwardMode 返回转发模式
func (e *IPVSEvent) ForwardMode() string {
	switch e.EventType {
	case EventNatXmit:
		return "NAT"
	case EventDrXmit:
		return "DR"
	case EventTunnelXmit:
		return "TUNNEL"
	default:
		return ""
	}
}

// String 返回事件的字符串表示
func (e *IPVSEvent) String() string {
	return fmt.Sprintf("[%s] %s %s:%d -> %s:%d -> %s:%d (%s)",
		e.EventType.String(),
		e.ProtocolName(),
		e.ClientIP, e.ClientPort,
		e.VIP, e.VPort,
		e.RealIP, e.RealPort,
		e.FormatLatency())
}

// IPVSChain 表示一个完整的 IPVS 调用链
type IPVSChain struct {
	ConnPtr    uint64
	StartTime  time.Time
	EndTime    time.Time
	Events     []*IPVSEvent
	ClientIP   net.IP
	ClientPort uint16
	VIP        net.IP
	VPort      uint16
	RealIP     net.IP
	RealPort   uint16
	Protocol   uint8
	Mode       string // NAT, DR, TUNNEL
	mu         sync.Mutex
}

// NewIPVSChain 创建新的调用链
func NewIPVSChain(event *IPVSEvent) *IPVSChain {
	return &IPVSChain{
		ConnPtr:    event.ConnPtr,
		StartTime:  time.Now(),
		Events:     []*IPVSEvent{event},
		ClientIP:   event.ClientIP,
		ClientPort: event.ClientPort,
		VIP:        event.VIP,
		VPort:      event.VPort,
		RealIP:     event.RealIP,
		RealPort:   event.RealPort,
		Protocol:   event.Protocol,
	}
}

// AddEvent 添加事件到调用链
func (c *IPVSChain) AddEvent(event *IPVSEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Events = append(c.Events, event)
	c.EndTime = time.Now()

	// 更新连接信息
	if event.RealIP != nil && !event.RealIP.IsUnspecified() {
		c.RealIP = event.RealIP
		c.RealPort = event.RealPort
	}

	// 更新转发模式
	mode := event.ForwardMode()
	if mode != "" {
		c.Mode = mode
	}
}

// TotalLatency 返回总延迟
func (c *IPVSChain) TotalLatency() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	var total uint64
	for _, e := range c.Events {
		total += e.LatencyNs
	}
	return time.Duration(total)
}

// IsComplete 检查调用链是否完整
func (c *IPVSChain) IsComplete() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	hasXmit := false
	for _, e := range c.Events {
		if e.EventType == EventNatXmit || e.EventType == EventDrXmit || e.EventType == EventTunnelXmit {
			hasXmit = true
			break
		}
	}
	return hasXmit
}

// String 返回调用链的字符串表示
func (c *IPVSChain) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	proto := "TCP"
	if c.Protocol == 17 {
		proto = "UDP"
	}

	mode := c.Mode
	if mode == "" {
		mode = "UNKNOWN"
	}

	return fmt.Sprintf("%s %s:%d -> %s:%d -> %s:%d [%s] (total: %v, events: %d)",
		proto,
		c.ClientIP, c.ClientPort,
		c.VIP, c.VPort,
		c.RealIP, c.RealPort,
		mode,
		c.TotalLatency(),
		len(c.Events))
}

// 辅助函数
// IP 地址在内核中是以 __be32（Big Endian/网络字节序）存储的
// eBPF 读取后直接作为 uint32 传递到用户空间
// 在 x86_64 上，uint32 是 Little Endian，所以需要用 LittleEndian 来解析
func uint32ToIP(ip uint32) net.IP {
	result := make(net.IP, 4)
	binary.LittleEndian.PutUint32(result, ip)
	return result
}

// 端口在内核中是以 __be16（Big Endian/网络字节序）存储的
// eBPF 读取后直接作为 uint16 传递到用户空间
// 在 x86_64 上，需要交换字节序
func ntohs(port uint16) uint16 {
	return (port >> 8) | (port << 8)
}

func bytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
