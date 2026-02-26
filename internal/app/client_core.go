package app

import (
	"sync/atomic"
)

type Client struct {
	running atomic.Bool

	tun         Tun
	peerManager PeerManager
	ws          WebSocketClient

	tunName string

	tunMsgQueue  MsgQueue
	peerMsgQueue MsgQueue
	wsMsgQueue   MsgQueue
}

func newClient() *Client {
	c := &Client{}
	c.tunMsgQueue = newMsgQueue()
	c.peerMsgQueue = newMsgQueue()
	c.wsMsgQueue = newMsgQueue()
	return c
}

func (c *Client) setName(name string) {
	c.tunName = name
	_ = c.tun.SetName(name)
	_ = c.ws.SetName(name)
}

func (c *Client) getName() string {
	return c.tunName
}

func (c *Client) getTunCidr() string {
	return c.ws.GetTunCidr()
}

func (c *Client) address() IP4 {
	return c.tun.GetIP()
}

func (c *Client) getTunMsgQueue() *MsgQueue {
	return &c.tunMsgQueue
}

func (c *Client) getPeerMsgQueue() *MsgQueue {
	return &c.peerMsgQueue
}

func (c *Client) getWsMsgQueue() *MsgQueue {
	return &c.wsMsgQueue
}

func (c *Client) setPassword(password string) {
	_ = c.ws.SetPassword(password)
	_ = c.peerManager.SetPassword(password)
}

func (c *Client) setWebSocket(uri string) {
	_ = c.ws.SetWsServerURI(uri)
}

func (c *Client) setTunAddress(cidr string) {
	_ = c.ws.SetAddress(cidr)
}

func (c *Client) setExptTunAddress(cidr string) {
	_ = c.ws.SetExptTunAddress(cidr)
}

func (c *Client) setVirtualMac(vmac string) {
	_ = c.ws.SetVirtualMac(vmac)
}

func (c *Client) setStun(stun string) {
	_ = c.peerManager.SetStun(stun)
}

func (c *Client) setDiscoveryInterval(interval int) {
	_ = c.peerManager.SetDiscoveryInterval(interval)
}

func (c *Client) setRouteCost(cost int) {
	_ = c.peerManager.SetRouteCost(cost)
}

func (c *Client) setPort(port int) {
	_ = c.peerManager.SetPort(port)
}

func (c *Client) setLocalhost(ip string) {
	_ = c.peerManager.SetLocalhost(ip)
}

func (c *Client) setMtu(mtu int) {
	_ = c.tun.SetMTU(mtu)
}

func (c *Client) run() {
	c.running.Store(true)

	if c.ws.Run(c) != 0 {
		return
	}
	if c.tun.Run(c) != 0 {
		return
	}
	if c.peerManager.Run(c) != 0 {
		return
	}

	_ = c.ws.Wait()
	_ = c.tun.Wait()
	_ = c.peerManager.Wait()

	c.wsMsgQueue.Clear()
	c.tunMsgQueue.Clear()
	c.peerMsgQueue.Clear()
}

func (c *Client) isRunning() bool {
	return c.running.Load()
}

func (c *Client) shutdown() {
	c.running.Store(false)
	_ = c.tun.Down()
}

func (c *Client) IsRunning() bool {
	return c.isRunning()
}

func (c *Client) Shutdown() {
	c.shutdown()
}

func (c *Client) GetTunMsgQueue() *MsgQueue {
	return c.getTunMsgQueue()
}

func (c *Client) GetPeerMsgQueue() *MsgQueue {
	return c.getPeerMsgQueue()
}

func (c *Client) GetWsMsgQueue() *MsgQueue {
	return c.getWsMsgQueue()
}

func (c *Client) Address() IP4 {
	return c.address()
}
