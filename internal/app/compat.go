package app

import (
	"candygo/internal/common"
	"candygo/internal/peer"
	"candygo/internal/tun"
	"candygo/internal/websocket"
)

type IP4 = common.IP4
type Msg = common.Msg
type MsgQueue = common.MsgQueue

type Tun = tun.Tun
type PeerManager = peer.PeerManager
type WebSocketClient = websocket.WebSocketClient
type WebSocketServer = websocket.WebSocketServer

var (
	newMsgQueue          = common.NewMsgQueue
	sleepOneSecond       = common.SleepOneSecond
	initThirdPartyLogger = common.InitThirdPartyLogger
	setDebug             = common.SetDebug
	debugf               = common.Debugf
	infof                = common.Infof
	warnf                = common.Warnf
	errorf               = common.Errorf
	criticalf            = common.Criticalf
)
