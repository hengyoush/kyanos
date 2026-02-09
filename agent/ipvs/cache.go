package ipvs

import (
	"fmt"
	"net"
	"sync"
	"time"

	"kyanos/common"
)

// IPVSCache 用于缓存 IPVS 事件，以便与网络连接关联
type IPVSCache struct {
	// key: "realIP:realPort" -> chain
	byRealServer map[string]*IPVSChain
	// key: "vip:vport" -> chain
	byVIP map[string]*IPVSChain
	mu    sync.RWMutex
	ttl   time.Duration
}

// NewIPVSCache 创建新的 IPVS 缓存
func NewIPVSCache(ttl time.Duration) *IPVSCache {
	common.AgentLog.Infof("[IPVS-Cache] Creating new IPVS cache with TTL=%v", ttl)
	cache := &IPVSCache{
		byRealServer: make(map[string]*IPVSChain),
		byVIP:        make(map[string]*IPVSChain),
		ttl:          ttl,
	}
	go cache.cleanup()
	return cache
}

// Add 添加 IPVS 调用链到缓存
func (c *IPVSCache) Add(chain *IPVSChain) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if chain.RealIP != nil && !chain.RealIP.IsUnspecified() {
		key := fmt.Sprintf("%s:%d", chain.RealIP.String(), chain.RealPort)
		c.byRealServer[key] = chain
		common.AgentLog.Infof("[IPVS-Cache] Added chain by RealServer: %s -> VIP=%s:%d", key, chain.VIP.String(), chain.VPort)
	}

	if chain.VIP != nil && !chain.VIP.IsUnspecified() {
		key := fmt.Sprintf("%s:%d", chain.VIP.String(), chain.VPort)
		c.byVIP[key] = chain
		common.AgentLog.Infof("[IPVS-Cache] Added chain by VIP: %s -> RealServer=%s:%d", key, chain.RealIP.String(), chain.RealPort)
	}

	common.AgentLog.Infof("[IPVS-Cache] Cache size: byRealServer=%d, byVIP=%d", len(c.byRealServer), len(c.byVIP))
}

// LookupByRealServer 根据真实服务器 IP:Port 查找 IPVS 信息
func (c *IPVSCache) LookupByRealServer(ip net.IP, port uint16) *IPVSChain {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := fmt.Sprintf("%s:%d", ip.String(), port)
	chain := c.byRealServer[key]
	if chain != nil {
		common.AgentLog.Infof("[IPVS-Cache] LookupByRealServer HIT: %s -> VIP=%s:%d", key, chain.VIP.String(), chain.VPort)
	} else {
		common.AgentLog.Debugf("[IPVS-Cache] LookupByRealServer MISS: %s", key)
	}
	return chain
}

// LookupByVIP 根据 VIP:VPort 查找 IPVS 信息
func (c *IPVSCache) LookupByVIP(ip net.IP, port uint16) *IPVSChain {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := fmt.Sprintf("%s:%d", ip.String(), port)
	chain := c.byVIP[key]
	if chain != nil {
		common.AgentLog.Infof("[IPVS-Cache] LookupByVIP HIT: %s -> RealServer=%s:%d", key, chain.RealIP.String(), chain.RealPort)
	} else {
		common.AgentLog.Debugf("[IPVS-Cache] LookupByVIP MISS: %s", key)
	}
	return chain
}

// LookupByAddr 根据地址字符串查找 IPVS 信息
func (c *IPVSCache) LookupByAddr(addr string, port uint16) *IPVSChain {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := fmt.Sprintf("%s:%d", addr, port)
	if chain, ok := c.byRealServer[key]; ok {
		return chain
	}
	if chain, ok := c.byVIP[key]; ok {
		return chain
	}
	return nil
}

// cleanup 定期清理过期的缓存
func (c *IPVSCache) cleanup() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		cleanedRealServer := 0
		cleanedVIP := 0
		for key, chain := range c.byRealServer {
			if now.Sub(chain.EndTime) > c.ttl {
				delete(c.byRealServer, key)
				cleanedRealServer++
			}
		}
		for key, chain := range c.byVIP {
			if now.Sub(chain.EndTime) > c.ttl {
				delete(c.byVIP, key)
				cleanedVIP++
			}
		}
		if cleanedRealServer > 0 || cleanedVIP > 0 {
			common.AgentLog.Debugf("[IPVS-Cache] Cleanup: removed %d RealServer entries, %d VIP entries", cleanedRealServer, cleanedVIP)
		}
		c.mu.Unlock()
	}
}

// 全局 IPVS 缓存实例
var globalCache *IPVSCache
var cacheOnce sync.Once

// GetGlobalCache 获取全局 IPVS 缓存
func GetGlobalCache() *IPVSCache {
	cacheOnce.Do(func() {
		common.AgentLog.Info("[IPVS-Cache] Initializing global IPVS cache")
		globalCache = NewIPVSCache(60 * time.Second)
	})
	return globalCache
}
