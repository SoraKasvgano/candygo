package app

import (
	"sync"
	"sync/atomic"
)

type jsonObject = map[string]any

type Instance struct {
	running atomic.Bool
	client  *Client
	mu      sync.RWMutex
}

func newInstance() *Instance {
	inst := &Instance{}
	inst.running.Store(true)
	return inst
}

func (i *Instance) is_running() bool {
	return i.running.Load()
}

func (i *Instance) exit() {
	i.running.Store(false)
	i.mu.RLock()
	c := i.client
	i.mu.RUnlock()
	if c != nil {
		c.shutdown()
	}
}

func (i *Instance) status() jsonObject {
	data := jsonObject{}
	i.mu.RLock()
	c := i.client
	i.mu.RUnlock()
	if c != nil {
		data["address"] = c.getTunCidr()
	}
	return data
}

func (i *Instance) create_client() *Client {
	c := newClient()
	i.mu.Lock()
	i.client = c
	i.mu.Unlock()
	return c
}

var (
	instanceMap   = map[string]*Instance{}
	instanceMutex sync.RWMutex
)

func try_create_instance(id string) (*Instance, bool) {
	instanceMutex.Lock()
	defer instanceMutex.Unlock()
	if _, ok := instanceMap[id]; ok {
		warnf("instance already exists: id=%s", id)
		return nil, false
	}
	inst := newInstance()
	instanceMap[id] = inst
	return inst, true
}

func try_erase_instance(id string) bool {
	instanceMutex.Lock()
	defer instanceMutex.Unlock()
	if _, ok := instanceMap[id]; !ok {
		return false
	}
	delete(instanceMap, id)
	return true
}

type clientAPI struct{}

func (api *clientAPI) run(id string, config jsonObject) bool {
	instance, ok := try_create_instance(id)
	if !ok {
		return false
	}

	infof("run enter: id=%s", id)
	for instance.is_running() {
		sleepOneSecond()
		c := instance.create_client()
		c.setName(jsonString(config, "name", ""))
		c.setPassword(jsonString(config, "password", ""))
		c.setWebSocket(jsonString(config, "websocket", ""))
		c.setTunAddress(jsonString(config, "tun", ""))
		c.setVirtualMac(jsonString(config, "vmac", ""))
		c.setExptTunAddress(jsonString(config, "expt", ""))
		c.setStun(jsonString(config, "stun", ""))
		c.setDiscoveryInterval(jsonInt(config, "discovery", 0))
		c.setRouteCost(jsonInt(config, "route", 0))
		c.setMtu(jsonInt(config, "mtu", 1400))
		c.setPort(jsonInt(config, "port", 0))
		c.setLocalhost(jsonString(config, "localhost", ""))
		c.run()
	}
	infof("run exit: id=%s", id)
	return try_erase_instance(id)
}

func (api *clientAPI) shutdown(id string) bool {
	instanceMutex.RLock()
	inst := instanceMap[id]
	instanceMutex.RUnlock()
	if inst == nil {
		warnf("instance not found: id=%s", id)
		return false
	}
	inst.exit()
	return true
}

func (api *clientAPI) status(id string) (jsonObject, bool) {
	instanceMutex.RLock()
	inst := instanceMap[id]
	instanceMutex.RUnlock()
	if inst == nil {
		return nil, false
	}
	return inst.status(), true
}

var (
	serverRunning atomic.Bool
	serverPtr     *Server
	serverMutex   sync.Mutex
)

type serverAPI struct{}

func (api *serverAPI) run(config jsonObject) bool {
	serverRunning.Store(true)
	for serverRunning.Load() {
		sleepOneSecond()
		s := &Server{}
		s.setWebSocket(jsonString(config, "websocket", ""))
		s.setPassword(jsonString(config, "password", ""))
		s.setDHCP(jsonString(config, "dhcp", ""))
		s.setSdwan(jsonString(config, "sdwan", ""))

		serverMutex.Lock()
		serverPtr = s
		serverMutex.Unlock()

		s.run()
	}
	return true
}

func (api *serverAPI) shutdown() bool {
	serverRunning.Store(false)
	serverMutex.Lock()
	s := serverPtr
	serverMutex.Unlock()
	if s != nil {
		s.shutdown()
	}
	return true
}

var (
	client = &clientAPI{}
	server = &serverAPI{}
)

func jsonString(config jsonObject, key string, def string) string {
	v, ok := config[key]
	if !ok || v == nil {
		return def
	}
	s, ok := v.(string)
	if !ok {
		return def
	}
	return s
}

func jsonInt(config jsonObject, key string, def int) int {
	v, ok := config[key]
	if !ok || v == nil {
		return def
	}
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case int32:
		return int(val)
	case int64:
		return int(val)
	default:
		return def
	}
}
