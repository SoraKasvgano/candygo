package peer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Stun struct {
	uri     string
	address *net.UDPAddr
	needed  atomic.Bool
	ip      IP4
	port    uint16
}

func (s *Stun) enabled() bool {
	return s.address != nil
}

func (s *Stun) update() int {
	if strings.TrimSpace(s.uri) == "" {
		s.address = nil
		return 0
	}
	parsed, err := url.Parse(s.uri)
	if err != nil {
		warnf("set stun server address failed: %v", err)
		return -1
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "3478"
	}
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, port))
	if err != nil {
		warnf("set stun server address failed: %v", err)
		return -1
	}
	s.address = addr
	return 0
}

type PeerRouteEntry struct {
	dst  IP4
	next IP4
	rtt  int32
}

type PeerManager struct {
	password  string
	localhost IP4

	stun Stun

	localP2PDisabled atomic.Bool

	client *Client

	msgThread  *Thread
	tickThread *Thread
	pollThread *Thread

	tunAddr Address

	ipPeerMutex sync.RWMutex
	ipPeerMap   map[IP4]*Peer

	rtTableMutex sync.RWMutex
	rtTableMap   map[IP4]PeerRouteEntry

	listenPort uint16

	socketMutex sync.Mutex
	socket      *net.UDPConn

	discoveryInterval int
	routeCost         int
	tickTick          uint64

	key []byte
}

func (p *PeerManager) ensureMaps() {
	if p.ipPeerMap == nil {
		p.ipPeerMap = make(map[IP4]*Peer)
	}
	if p.rtTableMap == nil {
		p.rtTableMap = make(map[IP4]PeerRouteEntry)
	}
}

func (p *PeerManager) setPassword(password string) int {
	p.password = password
	return 0
}

func (p *PeerManager) setStun(stun string) int {
	p.stun.uri = stun
	return 0
}

func (p *PeerManager) setDiscoveryInterval(interval int) int {
	p.discoveryInterval = interval
	return 0
}

func (p *PeerManager) setRouteCost(cost int) int {
	if cost < 0 {
		p.routeCost = 0
	} else if cost > 1000 {
		p.routeCost = 1000
	} else {
		p.routeCost = cost
	}
	return 0
}

func (p *PeerManager) setPort(port int) int {
	if port > 0 && port <= math.MaxUint16 {
		p.listenPort = uint16(port)
	}
	return 0
}

func (p *PeerManager) setLocalhost(ip string) int {
	_ = p.localhost.FromString(ip)
	return 0
}

func (p *PeerManager) run(client *Client) int {
	p.ensureMaps()
	p.client = client
	p.tickTick = uint64(randomUint32())
	p.localP2PDisabled.Store(false)

	if p.stun.update() != 0 {
		criticalf("update stun failed")
		return -1
	}

	p.msgThread = newThread(func() {
		defer func() {
			if r := recover(); r != nil {
				warnf("peer manager handle queue panic: %v", r)
			}
		}()
		debugf("start thread: peer manager msg")
		for p.getClient().isRunning() {
			if p.handlePeerQueue() != 0 {
				break
			}
		}
		p.getClient().shutdown()
		debugf("stop thread: peer manager msg")
	})
	return 0
}

func (p *PeerManager) wait() int {
	if p.msgThread != nil {
		p.msgThread.Join()
		p.msgThread = nil
	}
	if p.tickThread != nil {
		p.tickThread.Join()
		p.tickThread = nil
	}
	if p.pollThread != nil {
		p.pollThread.Join()
		p.pollThread = nil
	}

	if p.socket != nil {
		_ = p.socket.Close()
		p.socket = nil
	}

	p.rtTableMutex.Lock()
	p.rtTableMap = make(map[IP4]PeerRouteEntry)
	p.rtTableMutex.Unlock()

	p.ipPeerMutex.Lock()
	p.ipPeerMap = make(map[IP4]*Peer)
	p.ipPeerMutex.Unlock()

	return 0
}

func (p *PeerManager) getPassword() string {
	return p.password
}

func (p *PeerManager) handlePeerQueue() int {
	msg := p.getClient().getPeerMsgQueue().Read()
	switch msg.Kind {
	case TIMEOUT:
		return 0
	case PACKET:
		return p.handlePacket(msg)
	case TUNADDR:
		excludeIP := extractTunHostFromMsg(msg)
		if p.startTickThread(excludeIP) != 0 {
			return -1
		}
		if p.handleTunAddr(msg) != 0 {
			return -1
		}
	case SYSRT:
		p.localP2PDisabled.Store(true)
	case TRYP2P:
		_ = p.handleTryP2P(msg)
	case PUBINFO:
		_ = p.handlePubInfo(msg)
	default:
		warnf("unexcepted peer message type: %d", msg.Kind)
	}
	return 0
}

func (p *PeerManager) sendPacket(dst IP4, msg Msg) int {
	if p.sendPacketRelay(dst, msg) == 0 {
		return 0
	}
	if p.sendPacketDirect(dst, msg) == 0 {
		return 0
	}
	return -1
}

func (p *PeerManager) sendPacketDirect(dst IP4, msg Msg) int {
	p.ipPeerMutex.RLock()
	peer := p.ipPeerMap[dst]
	p.ipPeerMutex.RUnlock()
	if peer != nil {
		if _, ok := peer.isConnected(); ok {
			return peer.sendEncrypted(createPeerForward(msg.Data))
		}
	}
	return -1
}

func (p *PeerManager) sendPacketRelay(dst IP4, msg Msg) int {
	p.rtTableMutex.RLock()
	entry, ok := p.rtTableMap[dst]
	p.rtTableMutex.RUnlock()
	if !ok {
		return -1
	}
	return p.sendPacketDirect(entry.next, msg)
}

func (p *PeerManager) sendPubInfo(info CoreMsgPubInfo) int {
	info.Src = p.getClient().address()
	if info.Local {
		info.IP = p.localhost
		if p.socket != nil {
			if addr, ok := p.socket.LocalAddr().(*net.UDPAddr); ok {
				info.Port = uint16(addr.Port)
			}
		}
	} else {
		info.IP = p.stun.ip
		info.Port = p.stun.port
	}
	p.getClient().getWsMsgQueue().Write(newMsg(PUBINFO, info.Encode()))
	return 0
}

func (p *PeerManager) getTunIp() IP4 {
	return p.tunAddr.Host()
}

func (p *PeerManager) handlePacket(msg Msg) int {
	if len(msg.Data) < ip4HeaderSize {
		return 0
	}
	dst := ip4HeaderDAddr(msg.Data)
	if p.sendPacket(dst, msg) == 0 {
		return 0
	}
	p.getClient().getWsMsgQueue().Write(msg)
	return 0
}

func (p *PeerManager) handleTunAddr(msg Msg) int {
	if p.tunAddr.FromCidr(string(msg.Data)) != 0 {
		errorf("set tun addr failed: %s", string(msg.Data))
		return -1
	}
	data := make([]byte, 0, len(p.password)+4)
	data = append(data, []byte(p.password)...)
	host := p.tunAddr.Host()
	data = appendCompatIPKeyBytes(data, host)
	h := sha256.Sum256(data)
	p.key = h[:]
	return 0
}

func (p *PeerManager) handleTryP2P(msg Msg) int {
	var src IP4
	if src.FromString(string(msg.Data)) != 0 {
		return -1
	}

	p.ipPeerMutex.RLock()
	existing := p.ipPeerMap[src]
	p.ipPeerMutex.RUnlock()
	if existing != nil {
		existing.tryConnecct()
		return 0
	}

	p.ipPeerMutex.Lock()
	if p.ipPeerMap[src] == nil {
		p.ipPeerMap[src] = newPeer(src, p)
	}
	peer := p.ipPeerMap[src]
	p.ipPeerMutex.Unlock()
	peer.tryConnecct()
	return 0
}

func (p *PeerManager) handlePubInfo(msg Msg) int {
	info, ok := decodeCoreMsgPubInfo(msg.Data)
	if !ok {
		warnf("invalid public info size: %d", len(msg.Data))
		return 0
	}

	if info.Src == p.getClient().address() || info.Dst != p.getClient().address() {
		warnf("invalid public info: src=[%s] dst=[%s]", info.Src.ToString(), info.Dst.ToString())
		return 0
	}

	p.ipPeerMutex.RLock()
	peer := p.ipPeerMap[info.Src]
	p.ipPeerMutex.RUnlock()
	if peer != nil {
		peer.handlePubInfo(info.IP, info.Port, info.Local)
		return 0
	}

	p.ipPeerMutex.Lock()
	if p.ipPeerMap[info.Src] == nil {
		p.ipPeerMap[info.Src] = newPeer(info.Src, p)
	}
	peer = p.ipPeerMap[info.Src]
	p.ipPeerMutex.Unlock()
	peer.handlePubInfo(info.IP, info.Port, info.Local)
	return 0
}

func (p *PeerManager) startTickThread(excludeIP IP4) int {
	if p.localhost.Empty() {
		if local, err := detectLocalIPv4(excludeIP); err == nil {
			p.localhost = local
			debugf("localhost: %s", p.localhost.ToString())
		}
	}

	if p.initSocket() != 0 {
		return -1
	}
	if p.tickThread != nil {
		return 0
	}
	p.tickThread = newThread(func() {
		debugf("start thread: peer manager tick")
		for p.getClient().isRunning() {
			wake := time.Now().Add(time.Second)
			if p.tick() != 0 {
				break
			}
			time.Sleep(time.Until(wake))
		}
		p.getClient().shutdown()
		debugf("stop thread: peer manager tick")
	})
	return 0
}

func extractTunHostFromMsg(msg Msg) IP4 {
	var excludeIP IP4
	if len(msg.Data) == 0 {
		return excludeIP
	}
	var addr Address
	if addr.FromCidr(string(msg.Data)) != 0 {
		return excludeIP
	}
	return addr.Host()
}

func (p *PeerManager) tick() int {
	if p.discoveryInterval > 0 && p.stun.enabled() {
		p.tickTick++
		if p.tickTick%uint64(p.discoveryInterval) == 0 {
			p.getClient().getWsMsgQueue().Write(newMsg(DISCOVERY, nil))
		}
	}

	p.ipPeerMutex.RLock()
	for _, peer := range p.ipPeerMap {
		peer.tick()
	}
	p.ipPeerMutex.RUnlock()

	if p.stun.needed.Load() {
		p.sendStunRequest()
		p.stun.needed.Store(false)
	}
	return 0
}

func (p *PeerManager) initSocket() int {
	if p.socket != nil {
		return 0
	}
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: int(p.listenPort)}
	sock, err := net.ListenUDP("udp4", addr)
	if err != nil {
		criticalf("peer socket init failed: %v", err)
		return -1
	}
	_ = sock.SetWriteBuffer(16 * 1024 * 1024)
	_ = sock.SetReadBuffer(16 * 1024 * 1024)
	p.socket = sock
	if la, ok := sock.LocalAddr().(*net.UDPAddr); ok {
		debugf("listen port: %d", la.Port)
	}

	if p.pollThread == nil {
		p.pollThread = newThread(func() {
			debugf("start thread: peer manager poll")
			for p.getClient().isRunning() {
				if p.poll() != 0 {
					break
				}
			}
			p.getClient().shutdown()
			debugf("stop thread: peer manager poll")
		})
	}
	return 0
}

func (p *PeerManager) sendStunRequest() {
	if p.stun.address == nil || p.socket == nil {
		return
	}
	request := createStunRequest()
	if p.sendTo(request, p.stun.address) != len(request) {
		warnf("the stun request was not completely sent")
	}
}

func (p *PeerManager) handleStunResponse(buffer []byte) {
	if len(buffer) < 20 {
		debugf("invalid stun response length: %d", len(buffer))
		return
	}
	respType := binary.BigEndian.Uint16(buffer[0:2])
	if respType != 0x0101 {
		debugf("invalid stun response type: %d", respType)
		return
	}
	respLen := int(binary.BigEndian.Uint16(buffer[2:4]))
	if len(buffer) < 20+respLen {
		debugf("invalid stun response body length: %d", len(buffer))
		return
	}
	attr := buffer[20 : 20+respLen]
	pos := 0
	var ip uint32
	var port uint16
	for pos+4 <= len(attr) {
		atype := binary.BigEndian.Uint16(attr[pos : pos+2])
		alen := int(binary.BigEndian.Uint16(attr[pos+2 : pos+4]))
		if pos+4+alen > len(attr) {
			break
		}
		value := attr[pos+4 : pos+4+alen]
		if atype == 0x0001 && len(value) >= 8 {
			port = binary.BigEndian.Uint16(value[2:4])
			ip = binary.BigEndian.Uint32(value[4:8])
			break
		}
		if atype == 0x0020 && len(value) >= 8 {
			port = binary.BigEndian.Uint16(value[2:4]) ^ 0x2112
			ip = binary.BigEndian.Uint32(value[4:8]) ^ 0x2112a442
			break
		}
		pos += 4 + alen
	}
	if ip == 0 || port == 0 {
		warnf("stun response parse failed")
		return
	}
	p.stun.ip.FromUint32(ip)
	p.stun.port = port

	p.ipPeerMutex.RLock()
	for _, peer := range p.ipPeerMap {
		peer.handleStunResponse()
	}
	p.ipPeerMutex.RUnlock()
}

func (p *PeerManager) handleMessage(buffer []byte, address *net.UDPAddr) {
	if len(buffer) == 0 {
		return
	}
	switch buffer[0] {
	case PeerMsgKindHEARTBEAT:
		p.handleHeartbeatMessage(buffer, address)
	case PeerMsgKindFORWARD:
		p.handleForwardMessage(buffer, address)
	case PeerMsgKindDELAY:
		if p.clientRelayEnabled() {
			p.handleDelayMessage(buffer, address)
		}
	case PeerMsgKindROUTE:
		if p.clientRelayEnabled() {
			p.handleRouteMessage(buffer, address)
		}
	default:
		infof("udp4 unknown message: %s", address.String())
	}
}

func (p *PeerManager) handleHeartbeatMessage(buffer []byte, address *net.UDPAddr) {
	heartbeat, ok := decodePeerMsgHeartbeat(buffer)
	if !ok {
		debugf("udp4 heartbeat failed: len %d address %s", len(buffer), address.String())
		return
	}
	p.ipPeerMutex.RLock()
	peer := p.ipPeerMap[heartbeat.tunip]
	p.ipPeerMutex.RUnlock()
	if peer == nil {
		debugf("udp4 heartbeat find peer failed: tun ip %s", heartbeat.tunip.ToString())
		return
	}
	peer.handleHeartbeatMessage(address, heartbeat.ack)
}

func (p *PeerManager) handleForwardMessage(buffer []byte, _ *net.UDPAddr) {
	if len(buffer) < 1+ip4HeaderSize {
		warnf("invalid forward message: len=%d", len(buffer))
		return
	}
	packet := append([]byte{}, buffer[1:]...)
	headerDst := ip4HeaderDAddr(packet)
	if headerDst == p.getTunIp() {
		p.getClient().getTunMsgQueue().Write(newMsg(PACKET, packet))
	} else {
		p.getClient().getPeerMsgQueue().Write(newMsg(PACKET, packet))
	}
}

func (p *PeerManager) handleDelayMessage(buffer []byte, _ *net.UDPAddr) {
	header, ok := decodePeerMsgDelay(buffer)
	if !ok {
		warnf("invalid delay message: len=%d", len(buffer))
		return
	}

	if header.dst == p.getTunIp() {
		p.ipPeerMutex.RLock()
		peer := p.ipPeerMap[header.src]
		p.ipPeerMutex.RUnlock()
		if peer != nil {
			if _, ok := peer.isConnected(); ok {
				_ = peer.sendEncrypted(buffer)
			}
		}
		return
	}

	if header.src == p.getTunIp() {
		p.ipPeerMutex.RLock()
		peer := p.ipPeerMap[header.dst]
		p.ipPeerMutex.RUnlock()
		if peer != nil {
			peer.rtt = clampInt32(bootTime() - header.timestamp)
			_ = p.updateRtTable(PeerRouteEntry{dst: header.dst, next: header.dst, rtt: peer.rtt})
		}
	}
}

func (p *PeerManager) handleRouteMessage(buffer []byte, _ *net.UDPAddr) {
	if p.routeCost == 0 {
		return
	}
	header, ok := decodePeerMsgRoute(buffer)
	if !ok {
		warnf("invalid route message: len=%d", len(buffer))
		return
	}
	if header.dst != p.getTunIp() {
		_ = p.updateRtTable(PeerRouteEntry{dst: header.dst, next: header.next, rtt: header.rtt})
	}
}

func (p *PeerManager) poll() int {
	if p.socket == nil {
		return -1
	}
	_ = p.socket.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1500)
	n, address, err := p.socket.ReadFromUDP(buffer)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return 0
		}
		if isIgnorableUDPReadError(err) {
			return 0
		}
		return -1
	}
	if n <= 0 {
		return 0
	}
	payload := append([]byte{}, buffer[:n]...)
	if p.stun.address != nil && address.IP.Equal(p.stun.address.IP) && address.Port == p.stun.address.Port {
		p.handleStunResponse(payload)
		return 0
	}
	if plaintext, ok := p.decrypt(payload); ok {
		p.handleMessage(plaintext, address)
	}
	return 0
}

func (p *PeerManager) decrypt(ciphertext []byte) ([]byte, bool) {
	if len(p.key) != 32 {
		debugf("invalid key length: %d", len(p.key))
		return nil, false
	}
	if len(ciphertext) < 12+16 {
		debugf("invalid ciphertext length: %d", len(ciphertext))
		return nil, false
	}
	iv := ciphertext[:12]
	tag := ciphertext[12:28]
	enc := ciphertext[28:]

	block, err := aes.NewCipher(p.key)
	if err != nil {
		debugf("initialize cipher failed: %v", err)
		return nil, false
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		debugf("set iv length failed: %v", err)
		return nil, false
	}
	withTag := make([]byte, 0, len(enc)+len(tag))
	withTag = append(withTag, enc...)
	withTag = append(withTag, tag...)
	plaintext, err := gcm.Open(nil, iv, withTag, nil)
	if err != nil {
		debugf("decrypt final failed")
		return nil, false
	}
	return plaintext, true
}

func (p *PeerManager) sendTo(buffer []byte, address *net.UDPAddr) int {
	if p.socket == nil || address == nil {
		return -1
	}
	p.socketMutex.Lock()
	defer p.socketMutex.Unlock()
	n, err := p.socket.WriteToUDP(buffer, address)
	if err != nil {
		debugf("sendTo failed: %v", err)
		return -1
	}
	return n
}

func (p *PeerManager) getDiscoveryInterval() int {
	return p.discoveryInterval
}

func (p *PeerManager) clientRelayEnabled() bool {
	return p.routeCost > 0
}

func (p *PeerManager) getClient() *Client {
	return p.client
}

func (p *PeerManager) showRtChange(entry PeerRouteEntry) {
	rtt := "[deleted]"
	if entry.rtt != RTT_LIMIT {
		rtt = fmt.Sprintf("%d", entry.rtt)
	}
	debugf("route: dst=%s next=%s delay=%s", entry.dst.ToString(), entry.next.ToString(), rtt)
}

func (p *PeerManager) sendRtMessage(dst IP4, rtt int32) int {
	message := PeerMsgRoute{typeID: PeerMsgKindROUTE, dst: dst, next: p.getTunIp()}
	if rtt != RTT_LIMIT {
		rtt += int32(p.routeCost)
	}
	message.rtt = rtt
	payload := message.encode()

	p.ipPeerMutex.RLock()
	for _, peer := range p.ipPeerMap {
		if _, ok := peer.isConnected(); ok {
			_ = peer.sendEncrypted(payload)
		}
	}
	p.ipPeerMutex.RUnlock()
	return 0
}

func (p *PeerManager) updateRtTable(entry PeerRouteEntry) int {
	isDirect := entry.dst == entry.next
	isDelete := entry.rtt < 0 || entry.rtt > 1000

	p.rtTableMutex.Lock()
	defer p.rtTableMutex.Unlock()

	oldEntry, exists := p.rtTableMap[entry.dst]

	if isDirect && isDelete {
		for dst, rt := range p.rtTableMap {
			if rt.next == entry.next {
				rt.rtt = RTT_LIMIT
				_ = p.sendRtMessage(rt.dst, rt.rtt)
				p.showRtChange(rt)
				delete(p.rtTableMap, dst)
			}
		}
		return 0
	}

	if isDirect && !isDelete {
		if !exists || oldEntry.next == entry.next || oldEntry.rtt > entry.rtt {
			p.rtTableMap[entry.dst] = entry
			_ = p.sendRtMessage(entry.dst, entry.rtt)
			p.showRtChange(entry)
		}
		return 0
	}

	if !isDirect && isDelete {
		if exists && oldEntry.next == entry.next {
			oldEntry.rtt = RTT_LIMIT
			_ = p.sendRtMessage(oldEntry.dst, oldEntry.rtt)
			p.showRtChange(oldEntry)
			delete(p.rtTableMap, entry.dst)
		}
		return 0
	}

	if !isDirect && !isDelete {
		directEntry, ok := p.rtTableMap[entry.next]
		if !ok {
			return 0
		}
		rttNow := directEntry.rtt + entry.rtt
		if !exists || oldEntry.next == entry.next || oldEntry.rtt > rttNow {
			entry.rtt = rttNow
			p.rtTableMap[entry.dst] = entry
			_ = p.sendRtMessage(entry.dst, entry.rtt)
			p.showRtChange(entry)
		}
		return 0
	}

	return 0
}

func detectLocalIPv4(excludeIP IP4) (IP4, error) {
	var out IP4
	ifs, err := net.Interfaces()
	if err != nil {
		return out, err
	}

	type candidate struct {
		ip    net.IP
		iface string
		score int
	}

	pickBest := func(ignoreVirtual bool) *candidate {
		var best *candidate
		for _, iface := range ifs {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagPointToPoint != 0 {
				continue
			}
			if ignoreVirtual && isLikelyVirtualInterfaceName(iface.Name) {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				ip := ipnet.IP.To4()
				if ip == nil || !ip.IsGlobalUnicast() {
					continue
				}
				if !excludeIP.Empty() && ip.Equal(net.IP(excludeIP.Bytes())) {
					debugf("localhost skip tun ip: iface=%s ip=%s", iface.Name, ip.String())
					continue
				}
				score := scoreLocalIPv4(ip, iface.Name)
				debugf("localhost candidate: iface=%s ip=%s score=%d", iface.Name, ip.String(), score)
				if best == nil || score > best.score {
					best = &candidate{ip: append(net.IP(nil), ip...), iface: iface.Name, score: score}
				}
			}
		}
		return best
	}

	best := pickBest(true)
	if best == nil {
		best = pickBest(false)
	}
	if best == nil {
		return out, fmt.Errorf("no suitable local ip")
	}
	_ = out.FromBytes(best.ip.To4())
	debugf("localhost selected: iface=%s ip=%s score=%d", best.iface, best.ip.String(), best.score)
	return out, nil
}

func isLikelyVirtualInterfaceName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	keywords := []string{
		"wintun", "wireguard", "wg", "tailscale", "zerotier", "hamachi", "openvpn", "vpn",
		"tap", "tun", "utun", "docker", "veth", "vethernet", "hyper-v",
		"vmware", "virtualbox", "loopback", "bridge", "br-", "clash", "warp",
		"it-",
	}
	for _, k := range keywords {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

func scoreLocalIPv4(ip net.IP, ifaceName string) int {
	score := 0
	if isRFC1918(ip) {
		score += 300
	}
	if isCarrierGradeNAT(ip) {
		score += 80
	}
	if isPublicIPv4(ip) {
		score += 140
	}
	if isLinkLocalIPv4(ip) {
		score -= 500
	}
	if isLikelyVirtualInterfaceName(ifaceName) {
		score -= 1000
	}
	name := strings.ToLower(ifaceName)
	if strings.Contains(name, "ethernet") || strings.Contains(name, "wi-fi") || strings.Contains(name, "wlan") ||
		strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "en") {
		score += 40
	}
	return score
}

func isRFC1918(ip net.IP) bool {
	return ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168)
}

func isCarrierGradeNAT(ip net.IP) bool {
	return ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127
}

func isLinkLocalIPv4(ip net.IP) bool {
	return ip[0] == 169 && ip[1] == 254
}

func isPublicIPv4(ip net.IP) bool {
	return !isRFC1918(ip) && !isCarrierGradeNAT(ip) && !isLinkLocalIPv4(ip)
}
