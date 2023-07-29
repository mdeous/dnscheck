package dns

import (
	"github.com/miekg/dns"
	"sync"
)

type Cache struct {
	data map[string]map[string]map[uint16]*dns.Msg
	mut  *sync.RWMutex
}

func (c *Cache) Get(nameserver string, domain string, reqType uint16) *dns.Msg {
	c.mut.RLock()
	defer c.mut.RUnlock()
	if cachedDomains, exists := c.data[nameserver]; exists {
		if cachedTypes, exists := cachedDomains[domain]; exists {
			if cachedMsg, exists := cachedTypes[reqType]; exists {
				return cachedMsg
			}
		}
	}
	return nil
}

func (c *Cache) Put(nameserver string, domain string, reqType uint16, msg *dns.Msg) {
	c.mut.Lock()
	defer c.mut.Unlock()
	if _, exists := c.data[nameserver]; !exists {
		c.data[nameserver] = make(map[string]map[uint16]*dns.Msg)
	}
	if _, exists := c.data[nameserver][domain]; !exists {
		c.data[nameserver][domain] = make(map[uint16]*dns.Msg)
	}
	c.data[nameserver][domain][reqType] = msg
}

func NewCache() *Cache {
	return &Cache{
		data: make(map[string]map[string]map[uint16]*dns.Msg),
		mut:  &sync.RWMutex{},
	}
}
