package main

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
	_ = c.tun.setName(name)
	_ = c.ws.setName(name)
}

func (c *Client) getName() string {
	return c.tunName
}

func (c *Client) getTunCidr() string {
	return c.ws.getTunCidr()
}

func (c *Client) address() IP4 {
	return c.tun.getIP()
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
	_ = c.ws.setPassword(password)
	_ = c.peerManager.setPassword(password)
}

func (c *Client) setWebSocket(uri string) {
	_ = c.ws.setWsServerUri(uri)
}

func (c *Client) setTunAddress(cidr string) {
	_ = c.ws.setAddress(cidr)
}

func (c *Client) setExptTunAddress(cidr string) {
	_ = c.ws.setExptTunAddress(cidr)
}

func (c *Client) setVirtualMac(vmac string) {
	_ = c.ws.setVirtualMac(vmac)
}

func (c *Client) setStun(stun string) {
	_ = c.peerManager.setStun(stun)
}

func (c *Client) setDiscoveryInterval(interval int) {
	_ = c.peerManager.setDiscoveryInterval(interval)
}

func (c *Client) setRouteCost(cost int) {
	_ = c.peerManager.setRouteCost(cost)
}

func (c *Client) setPort(port int) {
	_ = c.peerManager.setPort(port)
}

func (c *Client) setLocalhost(ip string) {
	_ = c.peerManager.setLocalhost(ip)
}

func (c *Client) setMtu(mtu int) {
	_ = c.tun.setMTU(mtu)
}

func (c *Client) run() {
	c.running.Store(true)

	if c.ws.run(c) != 0 {
		return
	}
	if c.tun.run(c) != 0 {
		return
	}
	if c.peerManager.run(c) != 0 {
		return
	}

	_ = c.ws.wait()
	_ = c.tun.wait()
	_ = c.peerManager.wait()

	c.wsMsgQueue.clear()
	c.tunMsgQueue.clear()
	c.peerMsgQueue.clear()
}

func (c *Client) isRunning() bool {
	return c.running.Load()
}

func (c *Client) shutdown() {
	c.running.Store(false)
	_ = c.tun.down()
}
