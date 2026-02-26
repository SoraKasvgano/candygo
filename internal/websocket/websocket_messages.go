package websocket

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
)

const (
	WsMsgKindAUTH      = 0
	WsMsgKindFORWARD   = 1
	WsMsgKindEXPTTUN   = 2
	WsMsgKindUDP4CONN  = 3
	WsMsgKindVMAC      = 4
	WsMsgKindDISCOVERY = 5
	WsMsgKindROUTE     = 6
	WsMsgKindGENERAL   = 255
)

const GeSubTypeLOCALUDP4CONN = 0

type WsMsgAuth struct {
	typeID    uint8
	ip        IP4
	timestamp int64
	hash      [32]byte
}

func newWsMsgAuth(ip IP4) WsMsgAuth {
	return WsMsgAuth{typeID: WsMsgKindAUTH, ip: ip, timestamp: unixTime()}
}

func (m *WsMsgAuth) updateHash(password string) {
	data := make([]byte, 0, len(password)+4+8)
	data = append(data, []byte(password)...)
	data = append(data, m.ip.Bytes()...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(m.timestamp))
	data = append(data, ts...)
	m.hash = sha256.Sum256(data)
}

func (m *WsMsgAuth) check(password string) bool {
	localTime := unixTime()
	remoteTime := m.timestamp
	if math.Abs(float64(localTime-remoteTime)) > 300 {
		warnf("auth header timestamp check failed: server %d client %d", localTime, remoteTime)
	}
	reported := m.hash
	m.updateHash(password)
	if reported != m.hash {
		warnf("auth header hash check failed")
		return false
	}
	m.hash = reported
	return true
}

func (m WsMsgAuth) encode() []byte {
	out := make([]byte, 45)
	out[0] = m.typeID
	copy(out[1:5], m.ip.Bytes())
	binary.BigEndian.PutUint64(out[5:13], uint64(m.timestamp))
	copy(out[13:45], m.hash[:])
	return out
}

func decodeWsMsgAuth(data []byte) (WsMsgAuth, bool) {
	var m WsMsgAuth
	if len(data) < 45 {
		return m, false
	}
	m.typeID = data[0]
	_ = m.ip.FromBytes(data[1:5])
	m.timestamp = int64(binary.BigEndian.Uint64(data[5:13]))
	copy(m.hash[:], data[13:45])
	return m, true
}

type WsMsgExptTun struct {
	typeID    uint8
	timestamp int64
	cidr      string
	hash      [32]byte
}

func newWsMsgExptTun(cidr string) WsMsgExptTun {
	return WsMsgExptTun{typeID: WsMsgKindEXPTTUN, timestamp: unixTime(), cidr: cidr}
}

func (m *WsMsgExptTun) updateHash(password string) {
	data := make([]byte, 0, len(password)+8)
	data = append(data, []byte(password)...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(m.timestamp))
	data = append(data, ts...)
	m.hash = sha256.Sum256(data)
}

func (m *WsMsgExptTun) check(password string) bool {
	localTime := unixTime()
	remoteTime := m.timestamp
	if math.Abs(float64(localTime-remoteTime)) > 300 {
		warnf("expected address header timestamp check failed: server %d client %d", localTime, remoteTime)
	}
	reported := m.hash
	m.updateHash(password)
	if reported != m.hash {
		warnf("expected address header hash check failed")
		return false
	}
	m.hash = reported
	return true
}

func (m WsMsgExptTun) encode() []byte {
	out := make([]byte, 73)
	out[0] = m.typeID
	binary.BigEndian.PutUint64(out[1:9], uint64(m.timestamp))
	cidrBytes := []byte(m.cidr)
	if len(cidrBytes) > 32 {
		cidrBytes = cidrBytes[:32]
	}
	copy(out[9:41], cidrBytes)
	copy(out[41:73], m.hash[:])
	return out
}

func decodeWsMsgExptTun(data []byte) (WsMsgExptTun, bool) {
	var m WsMsgExptTun
	if len(data) < 73 {
		return m, false
	}
	m.typeID = data[0]
	m.timestamp = int64(binary.BigEndian.Uint64(data[1:9]))
	cidrRaw := data[9:41]
	end := 0
	for end < len(cidrRaw) && cidrRaw[end] != 0 {
		end++
	}
	m.cidr = string(cidrRaw[:end])
	copy(m.hash[:], data[41:73])
	return m, true
}

type WsMsgConn struct {
	typeID uint8
	src    IP4
	dst    IP4
	ip     IP4
	port   uint16
}

func newWsMsgConn() WsMsgConn {
	return WsMsgConn{typeID: WsMsgKindUDP4CONN}
}

func (m WsMsgConn) encode() []byte {
	out := make([]byte, 15)
	out[0] = m.typeID
	copy(out[1:5], m.src.Bytes())
	copy(out[5:9], m.dst.Bytes())
	copy(out[9:13], m.ip.Bytes())
	binary.BigEndian.PutUint16(out[13:15], m.port)
	return out
}

func decodeWsMsgConn(data []byte) (WsMsgConn, bool) {
	var m WsMsgConn
	if len(data) < 15 {
		return m, false
	}
	m.typeID = data[0]
	_ = m.src.FromBytes(data[1:5])
	_ = m.dst.FromBytes(data[5:9])
	_ = m.ip.FromBytes(data[9:13])
	m.port = binary.BigEndian.Uint16(data[13:15])
	return m, true
}

type WsMsgVMac struct {
	typeID    uint8
	vmac      [16]byte
	timestamp int64
	hash      [32]byte
}

func newWsMsgVMac(vmac string) WsMsgVMac {
	m := WsMsgVMac{typeID: WsMsgKindVMAC, timestamp: unixTime()}
	if len(vmac) >= len(m.vmac) {
		copy(m.vmac[:], []byte(vmac)[:len(m.vmac)])
	}
	return m
}

func (m *WsMsgVMac) updateHash(password string) {
	data := make([]byte, 0, len(password)+16+8)
	data = append(data, []byte(password)...)
	data = append(data, m.vmac[:]...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(m.timestamp))
	data = append(data, ts...)
	m.hash = sha256.Sum256(data)
}

func (m *WsMsgVMac) check(password string) bool {
	localTime := unixTime()
	remoteTime := m.timestamp
	if math.Abs(float64(localTime-remoteTime)) > 300 {
		warnf("vmac message timestamp check failed: server %d client %d", localTime, remoteTime)
	}
	reported := m.hash
	m.updateHash(password)
	if reported != m.hash {
		warnf("vmac message hash check failed")
		return false
	}
	m.hash = reported
	return true
}

func (m WsMsgVMac) encode() []byte {
	out := make([]byte, 57)
	out[0] = m.typeID
	copy(out[1:17], m.vmac[:])
	binary.BigEndian.PutUint64(out[17:25], uint64(m.timestamp))
	copy(out[25:57], m.hash[:])
	return out
}

func decodeWsMsgVMac(data []byte) (WsMsgVMac, bool) {
	var m WsMsgVMac
	if len(data) < 57 {
		return m, false
	}
	m.typeID = data[0]
	copy(m.vmac[:], data[1:17])
	m.timestamp = int64(binary.BigEndian.Uint64(data[17:25]))
	copy(m.hash[:], data[25:57])
	return m, true
}

type WsMsgDiscovery struct {
	typeID uint8
	src    IP4
	dst    IP4
}

func newWsMsgDiscovery() WsMsgDiscovery {
	return WsMsgDiscovery{typeID: WsMsgKindDISCOVERY}
}

func (m WsMsgDiscovery) encode() []byte {
	out := make([]byte, 9)
	out[0] = m.typeID
	copy(out[1:5], m.src.Bytes())
	copy(out[5:9], m.dst.Bytes())
	return out
}

func decodeWsMsgDiscovery(data []byte) (WsMsgDiscovery, bool) {
	var m WsMsgDiscovery
	if len(data) < 9 {
		return m, false
	}
	m.typeID = data[0]
	_ = m.src.FromBytes(data[1:5])
	_ = m.dst.FromBytes(data[5:9])
	return m, true
}

type WsMsgGeneral struct {
	typeID  uint8
	subtype uint8
	extra   uint16
	src     IP4
	dst     IP4
}

func (m WsMsgGeneral) encode() []byte {
	out := make([]byte, 12)
	out[0] = m.typeID
	out[1] = m.subtype
	binary.BigEndian.PutUint16(out[2:4], m.extra)
	copy(out[4:8], m.src.Bytes())
	copy(out[8:12], m.dst.Bytes())
	return out
}

func decodeWsMsgGeneral(data []byte) (WsMsgGeneral, bool) {
	var m WsMsgGeneral
	if len(data) < 12 {
		return m, false
	}
	m.typeID = data[0]
	m.subtype = data[1]
	m.extra = binary.BigEndian.Uint16(data[2:4])
	_ = m.src.FromBytes(data[4:8])
	_ = m.dst.FromBytes(data[8:12])
	return m, true
}

type WsMsgConnLocal struct {
	ge   WsMsgGeneral
	ip   IP4
	port uint16
}

func newWsMsgConnLocal() WsMsgConnLocal {
	return WsMsgConnLocal{
		ge: WsMsgGeneral{
			typeID:  WsMsgKindGENERAL,
			subtype: GeSubTypeLOCALUDP4CONN,
			extra:   0,
		},
	}
}

func (m WsMsgConnLocal) encode() []byte {
	out := make([]byte, 18)
	copy(out[:12], m.ge.encode())
	copy(out[12:16], m.ip.Bytes())
	binary.BigEndian.PutUint16(out[16:18], m.port)
	return out
}

func decodeWsMsgConnLocal(data []byte) (WsMsgConnLocal, bool) {
	var m WsMsgConnLocal
	if len(data) < 18 {
		return m, false
	}
	ge, ok := decodeWsMsgGeneral(data[:12])
	if !ok {
		return m, false
	}
	m.ge = ge
	_ = m.ip.FromBytes(data[12:16])
	m.port = binary.BigEndian.Uint16(data[16:18])
	return m, true
}

func encodeWsMsgSysRoute(entries []SysRouteEntry) []byte {
	out := make([]byte, 4+12*len(entries))
	out[0] = WsMsgKindROUTE
	out[1] = byte(len(entries))
	for i, entry := range entries {
		copy(out[4+i*12:4+(i+1)*12], entry.Encode())
	}
	return out
}

func decodeWsMsgSysRoute(data []byte) ([]SysRouteEntry, bool) {
	if len(data) < 4 || data[0] != WsMsgKindROUTE {
		return nil, false
	}
	size := int(data[1])
	if len(data) < 4+size*12 {
		return nil, false
	}
	entries := make([]SysRouteEntry, 0, size)
	for i := 0; i < size; i++ {
		rt, ok := decodeSysRouteEntry(data[4+i*12 : 4+(i+1)*12])
		if !ok {
			return nil, false
		}
		entries = append(entries, rt)
	}
	return entries, true
}
