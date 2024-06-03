package agent

import "sync"

type Connection4 struct {
	localIp        uint32
	remoteIp       uint32
	localPort      uint16
	remotePort     uint16
	protocol       agentTrafficProtocolT
	role           agentEndpointRoleT
	tgidFd         uint64
	TempKernEvents []*agentKernEvt
	TempConnEvents []*agentConnEvtT
}

type ConnManager struct {
	connMap *sync.Map
}

func InitConnManager() *ConnManager {
	return &ConnManager{connMap: new(sync.Map)}
}

func (c *ConnManager) AddConnection4(TgidFd uint64, conn *Connection4) error {
	c.connMap.Store(TgidFd, conn)
	return nil
}

func (c *ConnManager) RemoveConnection4(TgidFd uint64) {
	c.connMap.Delete(TgidFd)
}

func (c *ConnManager) findConnection4(TgidFd uint64) *Connection4 {
	v, _ := c.connMap.Load(TgidFd)
	if v != nil {
		return v.(*Connection4)
	} else {
		return nil
	}

}

func (c *Connection4) AddKernEvent(e *agentKernEvt) {
	c.TempKernEvents = append(c.TempKernEvents, e)
}

func (c *Connection4) AddConnEvent(e *agentConnEvtT) {
	c.TempConnEvents = append(c.TempConnEvents, e)
}

func (c *Connection4) ProtocolInferred() bool {
	return (c.protocol != agentTrafficProtocolTKProtocolUnknown) && (c.protocol != agentTrafficProtocolTKProtocolUnset)
}
