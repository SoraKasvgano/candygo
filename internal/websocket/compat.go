package websocket

import "candygo/internal/common"

type IP4 = common.IP4
type Address = common.Address
type Msg = common.Msg
type MsgQueue = common.MsgQueue
type CoreMsgPubInfo = common.CoreMsgPubInfo
type SysRouteEntry = common.SysRouteEntry
type Thread = common.Thread

const (
	TIMEOUT   = common.TIMEOUT
	PACKET    = common.PACKET
	TUNADDR   = common.TUNADDR
	SYSRT     = common.SYSRT
	TRYP2P    = common.TRYP2P
	PUBINFO   = common.PUBINFO
	DISCOVERY = common.DISCOVERY

	CANDY_VERSION = common.CANDY_VERSION
	ip4HeaderSize = common.Ip4HeaderSize
)

var (
	newThread            = common.NewThread
	newIP4               = common.NewIP4
	newMsg               = common.NewMsg
	decodeCoreMsgPubInfo = common.DecodeCoreMsgPubInfo
	decodeSysRouteEntry  = common.DecodeSysRouteEntry
	ip4HeaderSAddr       = common.Ip4HeaderSAddr
	ip4HeaderDAddr       = common.Ip4HeaderDAddr
	debugf               = common.Debugf
	infof                = common.Infof
	warnf                = common.Warnf
	errorf               = common.Errorf
	criticalf            = common.Criticalf
	bootTime             = common.BootTime
	unixTime             = common.UnixTime
	candySystem          = common.CandySystem
)

type runtimeClient interface {
	IsRunning() bool
	Shutdown()
	GetWsMsgQueue() *common.MsgQueue
	GetPeerMsgQueue() *common.MsgQueue
	GetTunMsgQueue() *common.MsgQueue
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

func (c *Client) getWsMsgQueue() *common.MsgQueue {
	if c == nil || c.runtime == nil {
		return nil
	}
	return c.runtime.GetWsMsgQueue()
}

func (c *Client) getPeerMsgQueue() *common.MsgQueue {
	if c == nil || c.runtime == nil {
		return nil
	}
	return c.runtime.GetPeerMsgQueue()
}

func (c *Client) getTunMsgQueue() *common.MsgQueue {
	if c == nil || c.runtime == nil {
		return nil
	}
	return c.runtime.GetTunMsgQueue()
}
