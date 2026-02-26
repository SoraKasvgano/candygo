package peer

import (
	"encoding/binary"
)

const (
	PeerMsgKindHEARTBEAT = 0
	PeerMsgKindFORWARD   = 1
	PeerMsgKindDELAY     = 2
	PeerMsgKindROUTE     = 4
)

func createPeerForward(packet []byte) []byte {
	out := make([]byte, 1+len(packet))
	out[0] = PeerMsgKindFORWARD
	copy(out[1:], packet)
	return out
}

func createStunRequest() []byte {
	out := make([]byte, 28)
	out[0] = 0x00
	out[1] = 0x01
	out[2] = 0x00
	out[3] = 0x08
	out[4] = 0x21
	out[5] = 0x12
	out[6] = 0xa4
	out[7] = 0x42
	binary.BigEndian.PutUint32(out[8:12], randomUint32())
	binary.BigEndian.PutUint32(out[12:16], randomUint32())
	binary.BigEndian.PutUint32(out[16:20], randomUint32())
	out[20] = 0x00
	out[21] = 0x03
	out[22] = 0x00
	out[23] = 0x04
	return out
}

type PeerMsgHeartbeat struct {
	kind  uint8
	tunip IP4
	ip    IP4
	port  uint16
	ack   uint8
}

func (m PeerMsgHeartbeat) encode() []byte {
	out := make([]byte, 12)
	out[0] = m.kind
	copy(out[1:5], m.tunip.Bytes())
	copy(out[5:9], m.ip.Bytes())
	binary.BigEndian.PutUint16(out[9:11], m.port)
	out[11] = m.ack
	return out
}

func decodePeerMsgHeartbeat(data []byte) (PeerMsgHeartbeat, bool) {
	var m PeerMsgHeartbeat
	if len(data) < 12 {
		return m, false
	}
	m.kind = data[0]
	_ = m.tunip.FromBytes(data[1:5])
	_ = m.ip.FromBytes(data[5:9])
	m.port = binary.BigEndian.Uint16(data[9:11])
	m.ack = data[11]
	return m, true
}

type PeerMsgDelay struct {
	typeID    uint8
	src       IP4
	dst       IP4
	timestamp int64
}

func (m PeerMsgDelay) encode() []byte {
	out := make([]byte, 17)
	out[0] = m.typeID
	copy(out[1:5], m.src.Bytes())
	copy(out[5:9], m.dst.Bytes())
	binary.BigEndian.PutUint64(out[9:17], uint64(m.timestamp))
	return out
}

func decodePeerMsgDelay(data []byte) (PeerMsgDelay, bool) {
	var m PeerMsgDelay
	if len(data) < 17 {
		return m, false
	}
	m.typeID = data[0]
	_ = m.src.FromBytes(data[1:5])
	_ = m.dst.FromBytes(data[5:9])
	m.timestamp = int64(binary.BigEndian.Uint64(data[9:17]))
	return m, true
}

type PeerMsgRoute struct {
	typeID uint8
	dst    IP4
	next   IP4
	rtt    int32
}

func (m PeerMsgRoute) encode() []byte {
	out := make([]byte, 13)
	out[0] = m.typeID
	copy(out[1:5], m.dst.Bytes())
	copy(out[5:9], m.next.Bytes())
	binary.BigEndian.PutUint32(out[9:13], uint32(m.rtt))
	return out
}

func decodePeerMsgRoute(data []byte) (PeerMsgRoute, bool) {
	var m PeerMsgRoute
	if len(data) < 13 {
		return m, false
	}
	m.typeID = data[0]
	_ = m.dst.FromBytes(data[1:5])
	_ = m.next.FromBytes(data[5:9])
	m.rtt = int32(binary.BigEndian.Uint32(data[9:13]))
	return m, true
}
