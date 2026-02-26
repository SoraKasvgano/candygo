package peer

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

	ip4HeaderSize = common.Ip4HeaderSize
)

var (
	newThread               = common.NewThread
	newIP4                  = common.NewIP4
	newMsg                  = common.NewMsg
	decodeCoreMsgPubInfo    = common.DecodeCoreMsgPubInfo
	ip4HeaderDAddr          = common.Ip4HeaderDAddr
	appendCompatIPKeyBytes  = common.AppendCompatIPKeyBytes
	clampInt32              = common.ClampInt32
	randomUint32            = common.RandomUint32
	bootTime                = common.BootTime
	debugf                  = common.Debugf
	infof                   = common.Infof
	warnf                   = common.Warnf
	errorf                  = common.Errorf
	criticalf               = common.Criticalf
	isIgnorableUDPReadError = common.IsIgnorableUDPReadError
)

type runtimeClient interface {
	IsRunning() bool
	Shutdown()
	GetPeerMsgQueue() *common.MsgQueue
	GetWsMsgQueue() *common.MsgQueue
	GetTunMsgQueue() *common.MsgQueue
	Address() common.IP4
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

func (c *Client) getPeerMsgQueue() *common.MsgQueue {
	if c == nil || c.runtime == nil {
		return nil
	}
	return c.runtime.GetPeerMsgQueue()
}

func (c *Client) getWsMsgQueue() *common.MsgQueue {
	if c == nil || c.runtime == nil {
		return nil
	}
	return c.runtime.GetWsMsgQueue()
}

func (c *Client) getTunMsgQueue() *common.MsgQueue {
	if c == nil || c.runtime == nil {
		return nil
	}
	return c.runtime.GetTunMsgQueue()
}

func (c *Client) address() common.IP4 {
	if c == nil || c.runtime == nil {
		return common.IP4{}
	}
	return c.runtime.Address()
}
