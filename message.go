package main

import (
	"encoding/binary"
	"time"
)

type MsgKind uint8

const (
	TIMEOUT MsgKind = iota
	PACKET
	TUNADDR
	SYSRT
	TRYP2P
	PUBINFO
	DISCOVERY
)

type Msg struct {
	kind MsgKind
	data []byte
}

func newMsg(kind MsgKind, data []byte) Msg {
	cp := make([]byte, len(data))
	copy(cp, data)
	return Msg{kind: kind, data: cp}
}

type MsgQueue struct {
	ch chan Msg
}

func newMsgQueue() MsgQueue {
	return MsgQueue{ch: make(chan Msg, 4096)}
}

func (q *MsgQueue) read() Msg {
	select {
	case m := <-q.ch:
		return m
	case <-time.After(time.Second):
		return Msg{kind: TIMEOUT}
	}
}

func (q *MsgQueue) write(msg Msg) {
	select {
	case q.ch <- msg:
	default:
		warnf("message queue is full, dropping message kind=%d", msg.kind)
	}
}

func (q *MsgQueue) clear() {
	for {
		select {
		case <-q.ch:
		default:
			return
		}
	}
}

type CoreMsgPubInfo struct {
	src   IP4
	dst   IP4
	ip    IP4
	port  uint16
	local bool
}

func (m CoreMsgPubInfo) encode() []byte {
	out := make([]byte, 15)
	copy(out[0:4], m.src.raw[:])
	copy(out[4:8], m.dst.raw[:])
	copy(out[8:12], m.ip.raw[:])
	binary.BigEndian.PutUint16(out[12:14], m.port)
	if m.local {
		out[14] = 1
	}
	return out
}

func decodeCoreMsgPubInfo(data []byte) (CoreMsgPubInfo, bool) {
	var m CoreMsgPubInfo
	if len(data) < 15 {
		return m, false
	}
	copy(m.src.raw[:], data[0:4])
	copy(m.dst.raw[:], data[4:8])
	copy(m.ip.raw[:], data[8:12])
	m.port = binary.BigEndian.Uint16(data[12:14])
	m.local = data[14] != 0
	return m, true
}
