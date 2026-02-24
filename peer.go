package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"sync"
	"time"
)

const (
	RTT_LIMIT = int32(2147483647)
	RETRY_MIN = 30
	RETRY_MAX = 3600
)

type PeerState int

const (
	INIT PeerState = iota
	PREPARING
	SYNCHRONIZING
	CONNECTING
	CONNECTED
	WAITING
	FAILED
)

type Peer struct {
	peerManager *PeerManager
	addr        IP4

	key []byte

	state PeerState
	ack   uint8
	retry int32

	rtt       int32
	tickCount uint32

	lastActiveTime time.Time

	socketAddressMutex sync.RWMutex
	wide               *net.UDPAddr
	local              *net.UDPAddr
	real               *net.UDPAddr
}

func newPeer(addr IP4, peerManager *PeerManager) *Peer {
	data := make([]byte, 0, len(peerManager.getPassword())+4)
	data = append(data, []byte(peerManager.getPassword())...)
	data = appendCompatIPKeyBytes(data, addr)
	k := sha256.Sum256(data)
	return &Peer{
		peerManager:    peerManager,
		addr:           addr,
		key:            k[:],
		state:          INIT,
		retry:          RETRY_MIN,
		rtt:            RTT_LIMIT,
		tickCount:      randomUint32(),
		lastActiveTime: time.Now(),
	}
}

func (p *Peer) getManager() *PeerManager {
	return p.peerManager
}

func (p *Peer) tryConnecct() {
	if p.state == INIT {
		p.updateState(PREPARING)
	}
}

func (p *Peer) encrypt(plaintext []byte) ([]byte, bool) {
	if len(p.key) != 32 {
		return nil, false
	}
	block, err := aes.NewCipher(p.key)
	if err != nil {
		debugf("encrypt initialize cipher failed: %v", err)
		return nil, false
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		debugf("encrypt initialize gcm failed: %v", err)
		return nil, false
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		debugf("generate random iv failed: %v", err)
		return nil, false
	}
	ciphertextWithTag := gcm.Seal(nil, iv, plaintext, nil)
	if len(ciphertextWithTag) < 16 {
		return nil, false
	}
	tag := ciphertextWithTag[len(ciphertextWithTag)-16:]
	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-16]
	result := make([]byte, 0, len(iv)+len(tag)+len(ciphertext))
	result = append(result, iv...)
	result = append(result, tag...)
	result = append(result, ciphertext...)
	return result, true
}

func (p *Peer) sendEncrypted(buffer []byte) int {
	if encrypted, ok := p.encrypt(buffer); ok {
		return p.send(encrypted)
	}
	return -1
}

func (p *Peer) checkActivityWithin(duration time.Duration) bool {
	return time.Since(p.lastActiveTime) < duration
}

func (p *Peer) isConnected() (int32, bool) {
	if p.state == CONNECTED {
		return p.rtt, true
	}
	return 0, false
}

func (p *Peer) updateState(state PeerState) bool {
	p.lastActiveTime = time.Now()
	if p.state == state {
		return false
	}
	debugf("state: %s %s => %s", p.addr.toString(), p.stateString(p.state), p.stateString(state))

	if state == INIT || state == WAITING || state == FAILED {
		p.resetState()
	}

	if p.state == WAITING && state == INIT {
		p.retry = p.retry * 2
		if p.retry > RETRY_MAX {
			p.retry = RETRY_MAX
		}
	} else if state == INIT || state == FAILED {
		p.retry = RETRY_MIN
	}

	p.state = state
	return true
}

func (p *Peer) stateString(state PeerState) string {
	switch state {
	case INIT:
		return "INIT"
	case PREPARING:
		return "PREPARING"
	case SYNCHRONIZING:
		return "SYNCHRONIZING"
	case CONNECTING:
		return "CONNECTING"
	case CONNECTED:
		return "CONNECTED"
	case WAITING:
		return "WAITING"
	case FAILED:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

func (p *Peer) handlePubInfo(ip IP4, port uint16, local bool) {
	addr := &net.UDPAddr{IP: net.IPv4(ip.raw[0], ip.raw[1], ip.raw[2], ip.raw[3]), Port: int(port)}
	p.socketAddressMutex.Lock()
	if local {
		p.local = addr
		p.socketAddressMutex.Unlock()
		return
	}
	p.wide = addr
	p.socketAddressMutex.Unlock()

	if p.state == CONNECTED {
		return
	}
	if p.state == SYNCHRONIZING {
		p.updateState(CONNECTING)
		return
	}
	if p.state != CONNECTING {
		p.updateState(PREPARING)
		info := CoreMsgPubInfo{dst: p.addr, local: true}
		_ = p.getManager().sendPubInfo(info)
		return
	}
}

func (p *Peer) handleStunResponse() {
	if p.state != PREPARING {
		return
	}
	if p.wide == nil {
		p.updateState(SYNCHRONIZING)
	} else {
		p.updateState(CONNECTING)
	}
	info := CoreMsgPubInfo{dst: p.addr}
	_ = p.getManager().sendPubInfo(info)
}

func (p *Peer) tick() {
	switch p.state {
	case INIT:
	case PREPARING:
		if p.getManager().stun.enabled() && p.checkActivityWithin(10*time.Second) {
			p.getManager().stun.needed.Store(true)
		} else {
			p.updateState(FAILED)
		}
	case SYNCHRONIZING:
		if p.checkActivityWithin(10 * time.Second) {
			p.sendHeartbeatMessage()
		} else {
			p.updateState(FAILED)
		}
	case CONNECTING:
		if p.checkActivityWithin(10 * time.Second) {
			p.sendHeartbeatMessage()
		} else {
			p.updateState(WAITING)
		}
	case CONNECTED:
		if p.checkActivityWithin(3 * time.Second) {
			p.sendHeartbeatMessage()
			if p.getManager().clientRelayEnabled() && p.tickCount%60 == 0 {
				p.sendDelayMessage()
			}
		} else {
			p.updateState(INIT)
			if p.getManager().clientRelayEnabled() {
				_ = p.getManager().updateRtTable(PeerRouteEntry{dst: p.addr, next: p.addr, rtt: RTT_LIMIT})
			}
		}
	case WAITING:
		if !p.checkActivityWithin(time.Duration(p.retry) * time.Second) {
			p.updateState(INIT)
		}
	case FAILED:
	}
	p.tickCount++
}

func (p *Peer) handleHeartbeatMessage(address *net.UDPAddr, heartbeatAck uint8) {
	if p.state == INIT || p.state == WAITING || p.state == FAILED {
		debugf("heartbeat peer state invalid: %s %s", p.addr.toString(), p.stateString(p.state))
		return
	}

	if !isLocalNetwork(address) {
		p.wide = address
	} else if !p.getManager().localP2PDisabled.Load() {
		p.local = address
	} else {
		return
	}

	p.socketAddressMutex.Lock()
	if p.real == nil || isLocalNetwork(address) || !isLocalNetwork(p.real) {
		p.real = address
	}
	p.socketAddressMutex.Unlock()

	if p.ack == 0 {
		p.ack = 1
	}

	if heartbeatAck != 0 && p.updateState(CONNECTED) {
		p.sendDelayMessage()
	}
}

func (p *Peer) send(buffer []byte) int {
	p.socketAddressMutex.RLock()
	real := p.real
	p.socketAddressMutex.RUnlock()
	if real == nil {
		return -1
	}
	if p.getManager().sendTo(buffer, real) == len(buffer) {
		return 0
	}
	return -1
}

func (p *Peer) sendHeartbeatMessage() {
	heartbeat := PeerMsgHeartbeat{kind: PeerMsgKindHEARTBEAT, tunip: p.getManager().getTunIp(), ack: p.ack}
	buffer, ok := p.encrypt(heartbeat.encode())
	if !ok {
		return
	}

	p.socketAddressMutex.RLock()
	defer p.socketAddressMutex.RUnlock()
	if p.real != nil && p.state == CONNECTED {
		heartbeat.ip = ipFromNetIP(p.real.IP)
		heartbeat.port = uint16(p.real.Port)
		_ = p.getManager().sendTo(buffer, p.real)
	}
	if p.wide != nil && p.state == CONNECTING {
		heartbeat.ip = ipFromNetIP(p.wide.IP)
		heartbeat.port = uint16(p.wide.Port)
		_ = p.getManager().sendTo(buffer, p.wide)
	}
	if p.local != nil && (p.state == PREPARING || p.state == SYNCHRONIZING || p.state == CONNECTING) {
		heartbeat.ip = ipFromNetIP(p.local.IP)
		heartbeat.port = uint16(p.local.Port)
		_ = p.getManager().sendTo(buffer, p.local)
	}
}

func (p *Peer) sendDelayMessage() {
	delay := PeerMsgDelay{typeID: PeerMsgKindDELAY, src: p.getManager().getTunIp(), dst: p.addr, timestamp: bootTime()}
	_ = p.sendEncrypted(delay.encode())
}

func (p *Peer) resetState() {
	p.socketAddressMutex.Lock()
	defer p.socketAddressMutex.Unlock()
	p.wide = nil
	p.local = nil
	p.real = nil
	p.ack = 0
	p.rtt = RTT_LIMIT
}

func isLocalNetwork(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	ip := addr.IP.To4()
	if ip == nil {
		errorf("unexpected ipv6 local address")
		return false
	}
	if ip[0] == 10 {
		return true
	}
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}
	if ip[0] == 169 && ip[1] == 254 {
		return true
	}
	return false
}

func ipFromNetIP(ip net.IP) IP4 {
	var out IP4
	v4 := ip.To4()
	if v4 != nil {
		copy(out.raw[:], v4)
	}
	return out
}
