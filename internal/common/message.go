package common

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
	Kind MsgKind
	Data []byte
}

func NewMsg(kind MsgKind, data []byte) Msg {
	cp := make([]byte, len(data))
	copy(cp, data)
	return Msg{Kind: kind, Data: cp}
}

func newMsg(kind MsgKind, data []byte) Msg {
	return NewMsg(kind, data)
}

type MsgQueue struct {
	ch chan Msg
}

func NewMsgQueue() MsgQueue {
	return MsgQueue{ch: make(chan Msg, 4096)}
}

func newMsgQueue() MsgQueue {
	return NewMsgQueue()
}

func (q *MsgQueue) Read() Msg {
	select {
	case m := <-q.ch:
		return m
	case <-time.After(time.Second):
		return Msg{Kind: TIMEOUT}
	}
}

func (q *MsgQueue) read() Msg {
	return q.Read()
}

func (q *MsgQueue) Write(msg Msg) {
	select {
	case q.ch <- msg:
	default:
		warnf("message queue is full, dropping message kind=%d", msg.Kind)
	}
}

func (q *MsgQueue) write(msg Msg) {
	q.Write(msg)
}

func (q *MsgQueue) Clear() {
	for {
		select {
		case <-q.ch:
		default:
			return
		}
	}
}

func (q *MsgQueue) clear() {
	q.Clear()
}

type CoreMsgPubInfo struct {
	Src   IP4
	Dst   IP4
	IP    IP4
	Port  uint16
	Local bool
}

func (m CoreMsgPubInfo) Encode() []byte {
	out := make([]byte, 15)
	copy(out[0:4], m.Src.raw[:])
	copy(out[4:8], m.Dst.raw[:])
	copy(out[8:12], m.IP.raw[:])
	binary.BigEndian.PutUint16(out[12:14], m.Port)
	if m.Local {
		out[14] = 1
	}
	return out
}

func (m CoreMsgPubInfo) encode() []byte {
	return m.Encode()
}

func DecodeCoreMsgPubInfo(data []byte) (CoreMsgPubInfo, bool) {
	var m CoreMsgPubInfo
	if len(data) < 15 {
		return m, false
	}
	copy(m.Src.raw[:], data[0:4])
	copy(m.Dst.raw[:], data[4:8])
	copy(m.IP.raw[:], data[8:12])
	m.Port = binary.BigEndian.Uint16(data[12:14])
	m.Local = data[14] != 0
	return m, true
}

func decodeCoreMsgPubInfo(data []byte) (CoreMsgPubInfo, bool) {
	return DecodeCoreMsgPubInfo(data)
}
