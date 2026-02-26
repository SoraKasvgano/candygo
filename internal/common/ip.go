package common

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"unsafe"
)

type IP4 struct {
	raw [4]byte
}

func newIP4(ip string) IP4 {
	var v IP4
	_ = v.fromString(ip)
	return v
}

func (ip *IP4) fromString(v string) int {
	addr := net.ParseIP(strings.TrimSpace(v))
	if addr == nil {
		ip.reset()
		return -1
	}
	v4 := addr.To4()
	if v4 == nil {
		ip.reset()
		return -1
	}
	copy(ip.raw[:], v4)
	return 0
}

func (ip *IP4) fromBytes(b []byte) int {
	if len(b) < 4 {
		ip.reset()
		return -1
	}
	copy(ip.raw[:], b[:4])
	return 0
}

func (ip IP4) bytes() []byte {
	out := make([]byte, 4)
	copy(out, ip.raw[:])
	return out
}

func (ip IP4) toString() string {
	return net.IPv4(ip.raw[0], ip.raw[1], ip.raw[2], ip.raw[3]).String()
}

func (ip IP4) toUint32() uint32 {
	return binary.BigEndian.Uint32(ip.raw[:])
}

func (ip *IP4) fromUint32(v uint32) {
	binary.BigEndian.PutUint32(ip.raw[:], v)
}

func (ip IP4) and(another IP4) IP4 {
	var out IP4
	for i := 0; i < 4; i++ {
		out.raw[i] = ip.raw[i] & another.raw[i]
	}
	return out
}

func (ip IP4) or(another IP4) IP4 {
	var out IP4
	for i := 0; i < 4; i++ {
		out.raw[i] = ip.raw[i] | another.raw[i]
	}
	return out
}

func (ip IP4) xor(another IP4) IP4 {
	var out IP4
	for i := 0; i < 4; i++ {
		out.raw[i] = ip.raw[i] ^ another.raw[i]
	}
	return out
}

func (ip IP4) not() IP4 {
	var out IP4
	for i := 0; i < 4; i++ {
		out.raw[i] = ^ip.raw[i]
	}
	return out
}

func (ip IP4) next() IP4 {
	v := ip.toUint32()
	v++
	var out IP4
	out.fromUint32(v)
	return out
}

func (ip IP4) toPrefix() int {
	count := 0
	for i := 0; i < 32; i++ {
		b := ip.raw[i/8]
		if (b & (0x80 >> uint(i%8))) == 0 {
			break
		}
		count++
	}
	return count
}

func (ip *IP4) fromPrefix(prefix int) int {
	if prefix < 0 || prefix > 32 {
		ip.reset()
		return -1
	}
	for i := range ip.raw {
		ip.raw[i] = 0
	}
	for i := 0; i < prefix; i++ {
		ip.raw[i/8] |= 0x80 >> uint(i%8)
	}
	return 0
}

func (ip IP4) empty() bool {
	return ip.raw[0] == 0 && ip.raw[1] == 0 && ip.raw[2] == 0 && ip.raw[3] == 0
}

func (ip *IP4) reset() {
	for i := range ip.raw {
		ip.raw[i] = 0
	}
}

type Address struct {
	host IP4
	mask IP4
}

func (a *Address) Host() IP4 {
	return a.host
}

func (a *Address) Mask() IP4 {
	return a.mask
}

func (a *Address) Net() IP4 {
	return a.host.and(a.mask)
}

func (a *Address) Next() Address {
	var next Address
	next.mask = a.mask
	next.host = a.Net().or(a.Mask().not().and(a.host.next()))
	return next
}

func (a *Address) isValid() bool {
	if a.mask.not().and(a.host).empty() {
		return false
	}
	if a.mask.or(a.host).not().empty() {
		return false
	}
	return true
}

func (a *Address) fromCidr(cidr string) int {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		a.host.reset()
		a.mask.reset()
		return 0
	}
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		warnf("address parse cidr failed: invalid cidr: %s", cidr)
		return -1
	}
	if a.host.fromString(parts[0]) != 0 {
		warnf("address parse cidr failed: invalid host: %s", cidr)
		return -1
	}
	p, err := strconv.Atoi(parts[1])
	if err != nil || a.mask.fromPrefix(p) != 0 {
		warnf("address parse cidr failed: invalid prefix: %s", cidr)
		return -1
	}
	return 0
}

func (a Address) toCidr() string {
	return fmt.Sprintf("%s/%d", a.host.toString(), a.mask.toPrefix())
}

func (a Address) empty() bool {
	return a.host.empty() && a.mask.empty()
}

type SysRouteEntry struct {
	Dst     IP4
	Mask    IP4
	Nexthop IP4
}

func (rt SysRouteEntry) encode() []byte {
	out := make([]byte, 12)
	copy(out[0:4], rt.Dst.raw[:])
	copy(out[4:8], rt.Mask.raw[:])
	copy(out[8:12], rt.Nexthop.raw[:])
	return out
}

func decodeSysRouteEntry(data []byte) (SysRouteEntry, bool) {
	var rt SysRouteEntry
	if len(data) < 12 {
		return rt, false
	}
	copy(rt.Dst.raw[:], data[0:4])
	copy(rt.Mask.raw[:], data[4:8])
	copy(rt.Nexthop.raw[:], data[8:12])
	return rt, true
}

const ip4HeaderSize = 20

func ip4HeaderIsIPv4(buffer []byte) bool {
	if len(buffer) < ip4HeaderSize {
		return false
	}
	return (buffer[0] >> 4) == 4
}

func ip4HeaderIsIPIP(buffer []byte) bool {
	if len(buffer) < ip4HeaderSize {
		return false
	}
	return buffer[9] == 0x04
}

func ip4HeaderSAddr(buffer []byte) IP4 {
	var ip IP4
	if len(buffer) >= 16 {
		copy(ip.raw[:], buffer[12:16])
	}
	return ip
}

func ip4HeaderDAddr(buffer []byte) IP4 {
	var ip IP4
	if len(buffer) >= 20 {
		copy(ip.raw[:], buffer[16:20])
	}
	return ip
}

func ip4HeaderSetSAddr(buffer []byte, ip IP4) {
	if len(buffer) >= 16 {
		copy(buffer[12:16], ip.raw[:])
	}
}

func ip4HeaderSetDAddr(buffer []byte, ip IP4) {
	if len(buffer) >= 20 {
		copy(buffer[16:20], ip.raw[:])
	}
}

func ip4HeaderSetProtocol(buffer []byte, protocol byte) {
	if len(buffer) >= 10 {
		buffer[9] = protocol
	}
}

func packIPIP(payload []byte, src, dst IP4) []byte {
	out := make([]byte, ip4HeaderSize+len(payload))
	copy(out[ip4HeaderSize:], payload)
	ip4HeaderSetProtocol(out, 0x04)
	ip4HeaderSetSAddr(out, src)
	ip4HeaderSetDAddr(out, dst)
	return out
}

func clampInt32(v int64) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	if v < math.MinInt32 {
		return math.MinInt32
	}
	return int32(v)
}

func appendCompatIPKeyBytes(dst []byte, ip IP4) []byte {
	// Keep parity with C++ key derivation: append raw memory bytes of hton(uint32_t(IP4)).
	if nativeLittleEndian() {
		return append(dst, ip.raw[3], ip.raw[2], ip.raw[1], ip.raw[0])
	}
	return append(dst, ip.raw[:]...)
}

func nativeLittleEndian() bool {
	var test uint16 = 0x0001
	b := (*[2]byte)(unsafe.Pointer(&test))
	return b[0] == 0x01
}
