package tun

import (
	"runtime"
	"sync"
)

type Tun struct {
	tunAddress string
	tunThread  *Thread
	msgThread  *Thread

	sysRtMutex sync.RWMutex
	sysRtTable []SysRouteEntry

	ip     IP4
	mask   IP4
	impl   *osTun
	client *Client
}

func (t *Tun) ensureImpl() {
	if t.impl == nil {
		t.impl = &osTun{mtu: 1400}
	}
}

func (t *Tun) setName(name string) int {
	t.ensureImpl()
	return t.impl.setName(name)
}

func (t *Tun) setMTU(mtu int) int {
	t.ensureImpl()
	return t.impl.setMTU(mtu)
}

func (t *Tun) run(client *Client) int {
	t.ensureImpl()
	t.client = client
	t.msgThread = newThread(func() {
		debugf("start thread: tun msg")
		defer func() {
			if r := recover(); r != nil {
				warnf("tun msg thread panic: %v", r)
			}
			t.getClient().shutdown()
			debugf("stop thread: tun msg")
		}()
		for t.getClient().isRunning() {
			if t.handleTunQueue() != 0 {
				break
			}
		}
	})
	return 0
}

func (t *Tun) wait() int {
	if t.msgThread != nil {
		t.msgThread.Join()
		t.msgThread = nil
	}
	if t.tunThread != nil {
		t.tunThread.Join()
		t.tunThread = nil
	}
	t.sysRtMutex.Lock()
	t.sysRtTable = nil
	t.sysRtMutex.Unlock()
	return 0
}

func (t *Tun) getIP() IP4 {
	return t.ip
}

func (t *Tun) getMask() IP4 {
	return t.mask
}

func (t *Tun) setAddress(cidr string) int {
	t.ensureImpl()
	var address Address
	if address.FromCidr(cidr) != 0 {
		return -1
	}
	infof("client address: %s", address.ToCidr())
	ip := address.Host()
	mask := address.Mask()
	if t.impl.setIP(ip) != 0 {
		return -1
	}
	if t.impl.setMask(mask) != 0 {
		return -1
	}
	if runtime.GOOS == "windows" {
		if t.impl.setPrefix(mask.ToPrefix()) != 0 {
			return -1
		}
	}
	t.ip = ip
	t.mask = mask
	t.tunAddress = cidr
	return 0
}

func (t *Tun) inTunNetwork(addr IP4) bool {
	return addr.And(t.getMask()) == t.getIP().And(t.getMask())
}

func (t *Tun) invalidSrcDst(src, dst IP4) bool {
	if t.inTunNetwork(src) && t.inTunNetwork(dst) {
		return false
	}
	if dst.ToUint32() == 0xffffffff {
		return false
	}
	if dst.ToUint32()&0xf0000000 == 0xe0000000 {
		return false
	}
	return true
}

func (t *Tun) handleTunDevice() int {
	buffer, err := t.read()
	if err != nil {
		if t.getClient().isRunning() {
			warnf("tun read failed: %v", err)
		}
		return -1
	}
	if len(buffer) == 0 {
		return 0
	}
	if len(buffer) < ip4HeaderSize {
		return 0
	}
	if !ip4HeaderIsIPv4(buffer) {
		return 0
	}

	headerDst := ip4HeaderDAddr(buffer)
	if headerDst == t.getIP() {
		_ = t.write(buffer)
		return 0
	}

	nextHop := func() IP4 {
		t.sysRtMutex.RLock()
		defer t.sysRtMutex.RUnlock()
		for _, rt := range t.sysRtTable {
			if headerDst.And(rt.Mask) == rt.Dst {
				return rt.Nexthop
			}
		}
		return IP4{}
	}()

	if !nextHop.Empty() {
		buffer = packIPIP(buffer, t.getIP(), nextHop)
		headerDst = ip4HeaderDAddr(buffer)
	}

	headerSrc := ip4HeaderSAddr(buffer)
	if t.invalidSrcDst(headerSrc, headerDst) {
		debugf("packet src=%s or dst=%s not in tun network, dropping", headerSrc.ToString(), headerDst.ToString())
		return 0
	}

	t.client.getPeerMsgQueue().Write(newMsg(PACKET, buffer))
	return 0
}

func (t *Tun) handleTunQueue() int {
	msg := t.client.getTunMsgQueue().Read()
	switch msg.Kind {
	case TIMEOUT:
		return 0
	case PACKET:
		return t.handlePacket(msg)
	case TUNADDR:
		return t.handleTunAddr(msg)
	case SYSRT:
		return t.handleSysRt(msg)
	default:
		warnf("unexcepted tun message type: %d", msg.Kind)
	}
	return 0
}

func (t *Tun) handlePacket(msg Msg) int {
	if len(msg.Data) < ip4HeaderSize {
		warnf("invalid IPv4 packet size: %d", len(msg.Data))
		return 0
	}
	data := msg.Data
	if ip4HeaderIsIPIP(data) {
		if len(data) < ip4HeaderSize {
			return 0
		}
		data = data[ip4HeaderSize:]
	}
	_ = t.write(data)
	return 0
}

func (t *Tun) handleTunAddr(msg Msg) int {
	if t.setAddress(string(msg.Data)) != 0 {
		return -1
	}
	if t.up() != 0 {
		criticalf("tun up failed")
		return -1
	}

	t.tunThread = newThread(func() {
		debugf("start thread: tun")
		defer func() {
			if r := recover(); r != nil {
				warnf("tun thread panic: %v", r)
			}
			t.getClient().shutdown()
			debugf("stop thread: tun")

			if t.down() != 0 {
				criticalf("tun down failed")
			}
		}()
		for t.getClient().isRunning() {
			if t.handleTunDevice() != 0 {
				break
			}
		}
	})

	return 0
}

func (t *Tun) handleSysRt(msg Msg) int {
	rt, ok := decodeSysRouteEntry(msg.Data)
	if !ok {
		warnf("invalid route message size: %d", len(msg.Data))
		return 0
	}
	if rt.Nexthop != t.getIP() {
		infof("route: %s/%d via %s", rt.Dst.ToString(), rt.Mask.ToPrefix(), rt.Nexthop.ToString())
		if t.setSysRtTable(rt) != 0 {
			return -1
		}
	}
	return 0
}

func (t *Tun) setSysRtTable(entry SysRouteEntry) int {
	t.sysRtMutex.Lock()
	t.sysRtTable = append(t.sysRtTable, entry)
	t.sysRtMutex.Unlock()
	return t.impl.setSysRtTable(entry.Dst, entry.Mask, entry.Nexthop)
}

func (t *Tun) getClient() *Client {
	return t.client
}

func (t *Tun) up() int {
	t.ensureImpl()
	return t.impl.up()
}

func (t *Tun) down() int {
	t.ensureImpl()
	return t.impl.down()
}

func (t *Tun) read() ([]byte, error) {
	t.ensureImpl()
	return t.impl.read()
}

func (t *Tun) write(buffer []byte) int {
	t.ensureImpl()
	if err := t.impl.write(buffer); err != nil {
		warnf("tun write failed: %v", err)
		return -1
	}
	return 0
}
