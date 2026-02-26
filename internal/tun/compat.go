package tun

import "candygo/internal/common"

type IP4 = common.IP4
type Address = common.Address
type Msg = common.Msg
type MsgQueue = common.MsgQueue
type SysRouteEntry = common.SysRouteEntry
type Thread = common.Thread

const (
	TIMEOUT = common.TIMEOUT
	PACKET  = common.PACKET
	TUNADDR = common.TUNADDR
	SYSRT   = common.SYSRT

	ip4HeaderSize = common.Ip4HeaderSize
)

var (
	newThread           = common.NewThread
	newMsg              = common.NewMsg
	decodeSysRouteEntry = common.DecodeSysRouteEntry
	ip4HeaderIsIPv4     = common.Ip4HeaderIsIPv4
	ip4HeaderIsIPIP     = common.Ip4HeaderIsIPIP
	ip4HeaderDAddr      = common.Ip4HeaderDAddr
	packIPIP            = common.PackIPIP
	debugf              = common.Debugf
	infof               = common.Infof
	warnf               = common.Warnf
	errorf              = common.Errorf
	criticalf           = common.Criticalf
)

type runtimeClient interface {
	IsRunning() bool
	Shutdown()
	GetTunMsgQueue() *common.MsgQueue
	GetPeerMsgQueue() *common.MsgQueue
}

type Client struct {
	runtime runtimeClient
}

func wrapClient(runtime runtimeClient) *Client {
	if runtime == nil {
		return nil
	}
	return &Client{runtime: runtime}
}

func (c *Client) isRunning() bool {
	return c != nil && c.runtime != nil && c.runtime.IsRunning()
}

func (c *Client) shutdown() {
	if c != nil && c.runtime != nil {
		c.runtime.Shutdown()
	}
}

func (c *Client) getTunMsgQueue() *common.MsgQueue {
	if c == nil || c.runtime == nil {
		return nil
	}
	return c.runtime.GetTunMsgQueue()
}

func (c *Client) getPeerMsgQueue() *common.MsgQueue {
	if c == nil || c.runtime == nil {
		return nil
	}
	return c.runtime.GetPeerMsgQueue()
}
