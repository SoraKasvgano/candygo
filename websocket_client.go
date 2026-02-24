package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type WebSocketClient struct {
	msgThread  *Thread
	wsThread   *Thread
	pingThread *Thread

	ws        *websocket.Conn
	writeMu   sync.Mutex
	timestamp atomic.Int64

	wsServerUri string
	exptTunCidr string
	tunCidr     string
	vmac        string
	name        string
	password    string

	addressUpdateCallback func(string) int

	pingMessage string

	client *Client
}

func (w *WebSocketClient) setName(name string) int {
	w.name = name
	return 0
}

func (w *WebSocketClient) setPassword(password string) int {
	w.password = password
	return 0
}

func (w *WebSocketClient) setWsServerUri(uri string) int {
	w.wsServerUri = uri
	return 0
}

func (w *WebSocketClient) setExptTunAddress(cidr string) int {
	w.exptTunCidr = cidr
	return 0
}

func (w *WebSocketClient) setAddress(cidr string) int {
	w.tunCidr = cidr
	return 0
}

func (w *WebSocketClient) setVirtualMac(vmac string) int {
	w.vmac = vmac
	return 0
}

func (w *WebSocketClient) setTunUpdateCallback(callback func(string) int) int {
	w.addressUpdateCallback = callback
	return 0
}

func (w *WebSocketClient) getTunCidr() string {
	return w.tunCidr
}

func (w *WebSocketClient) run(client *Client) int {
	w.client = client
	if w.connect() != 0 {
		criticalf("websocket client connect failed")
		return -1
	}

	w.sendVirtualMacMsg()
	if strings.TrimSpace(w.tunCidr) == "" {
		w.sendExptTunMsg()
	} else {
		w.sendAuthMsg()
	}

	w.msgThread = newThread(func() {
		debugf("start thread: websocket client msg")
		for w.getClient().isRunning() {
			w.handleWsQueue()
		}
		w.getClient().shutdown()
		debugf("stop thread: websocket client msg")
	})

	w.wsThread = newThread(func() {
		defer func() {
			if r := recover(); r != nil {
				warnf("websocket client ws panic: %v", r)
			}
		}()
		debugf("start thread: websocket client ws")
		for w.getClient().isRunning() {
			if w.handleWsConn() != 0 {
				break
			}
		}
		w.getClient().shutdown()
		debugf("stop thread: websocket client ws")
		_ = w.disconnect()
	})

	w.pingThread = newThread(func() {
		debugf("start thread: websocket client ping")
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for w.getClient().isRunning() {
			<-ticker.C
			if !w.getClient().isRunning() {
				break
			}
			w.sendPingMessage()
			if bootTime()-w.timestamp.Load() > 30000 {
				warnf("websocket pong timeout")
				_ = w.disconnect()
				break
			}
		}
		debugf("stop thread: websocket client ping")
	})

	return 0
}

func (w *WebSocketClient) wait() int {
	if w.msgThread != nil {
		w.msgThread.join()
		w.msgThread = nil
	}
	if w.wsThread != nil {
		w.wsThread.join()
		w.wsThread = nil
	}
	if w.pingThread != nil {
		w.pingThread.join()
		w.pingThread = nil
	}
	return 0
}

func (w *WebSocketClient) handleWsQueue() {
	msg := w.client.getWsMsgQueue().read()
	switch msg.kind {
	case TIMEOUT:
		return
	case PACKET:
		w.handlePacket(msg)
	case PUBINFO:
		w.handlePubInfo(msg)
	case DISCOVERY:
		w.handleDiscovery(msg)
	default:
		warnf("unexcepted websocket message type: %d", msg.kind)
	}
}

func (w *WebSocketClient) handlePacket(msg Msg) {
	buffer := make([]byte, 1+len(msg.data))
	buffer[0] = WsMsgKindFORWARD
	copy(buffer[1:], msg.data)
	w.sendFrame(buffer, websocket.BinaryMessage)
}

func (w *WebSocketClient) handlePubInfo(msg Msg) {
	info, ok := decodeCoreMsgPubInfo(msg.data)
	if !ok {
		warnf("invalid pubinfo message size: %d", len(msg.data))
		return
	}
	if info.local {
		buffer := newWsMsgConnLocal()
		buffer.ge.src = info.src
		buffer.ge.dst = info.dst
		buffer.ip = info.ip
		buffer.port = info.port
		w.sendFrame(buffer.encode(), websocket.BinaryMessage)
		return
	}
	buffer := newWsMsgConn()
	buffer.src = info.src
	buffer.dst = info.dst
	buffer.ip = info.ip
	buffer.port = info.port
	w.sendFrame(buffer.encode(), websocket.BinaryMessage)
}

func (w *WebSocketClient) handleDiscovery(_ Msg) {
	w.sendDiscoveryMsg(newIP4("255.255.255.255"))
}

func (w *WebSocketClient) handleWsConn() int {
	w.writeMu.Lock()
	conn := w.ws
	w.writeMu.Unlock()
	if conn == nil {
		return -1
	}
	messageType, buffer, err := conn.ReadMessage()
	if err != nil {
		if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
			infof("abnormal disconnect")
			return -1
		}
		warnf("handle ws conn failed: %v", err)
		return -1
	}

	if messageType == websocket.BinaryMessage {
		if len(buffer) == 0 {
			return 0
		}
		w.timestamp.Store(bootTime())
		w.handleWsMsg(buffer)
		return 0
	}
	if messageType == websocket.CloseMessage {
		infof("websocket close")
		return -1
	}
	return 0
}

func (w *WebSocketClient) handleWsMsg(buffer []byte) {
	if len(buffer) == 0 {
		return
	}
	switch buffer[0] {
	case WsMsgKindFORWARD:
		w.handleForwardMsg(buffer)
	case WsMsgKindEXPTTUN:
		w.handleExptTunMsg(buffer)
	case WsMsgKindUDP4CONN:
		w.handleUdp4ConnMsg(buffer)
	case WsMsgKindDISCOVERY:
		w.handleDiscoveryMsg(buffer)
	case WsMsgKindROUTE:
		w.handleRouteMsg(buffer)
	case WsMsgKindGENERAL:
		w.handleGeneralMsg(buffer)
	default:
		debugf("unknown websocket message kind: %d", buffer[0])
	}
}

func (w *WebSocketClient) handleForwardMsg(buffer []byte) {
	if len(buffer) < 1+ip4HeaderSize {
		warnf("invalid forward message: len=%d", len(buffer))
		return
	}
	packet := append([]byte{}, buffer[1:]...)
	headerSrc := ip4HeaderSAddr(packet)
	w.client.getPeerMsgQueue().write(newMsg(TRYP2P, []byte(headerSrc.toString())))
	w.client.getTunMsgQueue().write(newMsg(PACKET, packet))
}

func (w *WebSocketClient) handleExptTunMsg(buffer []byte) {
	header, ok := decodeWsMsgExptTun(buffer)
	if !ok {
		warnf("invalid expt tun message: len=%d", len(buffer))
		return
	}
	var exptTun Address
	if exptTun.fromCidr(header.cidr) != 0 {
		warnf("invalid expt tun cidr: %s", header.cidr)
		return
	}
	w.tunCidr = exptTun.toCidr()
	w.sendAuthMsg()
}

func (w *WebSocketClient) handleUdp4ConnMsg(buffer []byte) {
	header, ok := decodeWsMsgConn(buffer)
	if !ok {
		warnf("invalid udp4conn message: len=%d", len(buffer))
		return
	}
	info := CoreMsgPubInfo{src: header.src, dst: header.dst, ip: header.ip, port: header.port}
	w.client.getPeerMsgQueue().write(newMsg(PUBINFO, info.encode()))
}

func (w *WebSocketClient) handleDiscoveryMsg(buffer []byte) {
	header, ok := decodeWsMsgDiscovery(buffer)
	if !ok {
		warnf("invalid discovery message: len=%d", len(buffer))
		return
	}
	if header.dst == newIP4("255.255.255.255") {
		w.sendDiscoveryMsg(header.src)
	}
	w.client.getPeerMsgQueue().write(newMsg(TRYP2P, []byte(header.src.toString())))
}

func (w *WebSocketClient) handleRouteMsg(buffer []byte) {
	entries, ok := decodeWsMsgSysRoute(buffer)
	if !ok {
		warnf("invalid route message: len=%d", len(buffer))
		return
	}
	for _, rt := range entries {
		w.client.getTunMsgQueue().write(newMsg(SYSRT, rt.encode()))
		w.client.getPeerMsgQueue().write(newMsg(SYSRT, nil))
	}
}

func (w *WebSocketClient) handleGeneralMsg(buffer []byte) {
	header, ok := decodeWsMsgConnLocal(buffer)
	if !ok {
		warnf("invalid udp4conn local message: len=%d", len(buffer))
		return
	}
	info := CoreMsgPubInfo{src: header.ge.src, dst: header.ge.dst, ip: header.ip, port: header.port, local: true}
	w.client.getPeerMsgQueue().write(newMsg(PUBINFO, info.encode()))
}

func (w *WebSocketClient) sendFrame(buffer []byte, flags int) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if w.ws == nil {
		return
	}
	if err := w.ws.WriteMessage(flags, buffer); err != nil {
		criticalf("websocket send frame failed: %v", err)
	}
}

func (w *WebSocketClient) sendVirtualMacMsg() {
	buffer := newWsMsgVMac(w.vmac)
	buffer.updateHash(w.password)
	w.sendFrame(buffer.encode(), websocket.BinaryMessage)
}

func (w *WebSocketClient) sendExptTunMsg() {
	var exptTun Address
	_ = exptTun.fromCidr(w.exptTunCidr)
	buffer := newWsMsgExptTun(exptTun.toCidr())
	buffer.updateHash(w.password)
	w.sendFrame(buffer.encode(), websocket.BinaryMessage)
}

func (w *WebSocketClient) sendAuthMsg() {
	var address Address
	if address.fromCidr(w.tunCidr) != 0 {
		warnf("invalid auth tun cidr: %s", w.tunCidr)
		return
	}
	buffer := newWsMsgAuth(address.Host())
	buffer.updateHash(w.password)
	w.sendFrame(buffer.encode(), websocket.BinaryMessage)
	w.client.getTunMsgQueue().write(newMsg(TUNADDR, []byte(address.toCidr())))
	w.client.getPeerMsgQueue().write(newMsg(TUNADDR, []byte(address.toCidr())))
	if w.addressUpdateCallback != nil {
		_ = w.addressUpdateCallback(address.toCidr())
	}
	w.sendPingMessage()
}

func (w *WebSocketClient) sendDiscoveryMsg(dst IP4) {
	var address Address
	if address.fromCidr(w.tunCidr) != 0 {
		return
	}
	buffer := newWsMsgDiscovery()
	buffer.dst = dst
	buffer.src = address.Host()
	w.sendFrame(buffer.encode(), websocket.BinaryMessage)
}

func (w *WebSocketClient) hostName() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hostname
}

func (w *WebSocketClient) sendPingMessage() {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if w.ws == nil {
		return
	}
	if err := w.ws.WriteControl(websocket.PingMessage, []byte(w.pingMessage), time.Now().Add(time.Second)); err != nil {
		debugf("send ping failed: %v", err)
	}
}

func (w *WebSocketClient) connect() int {
	parsed, err := url.Parse(w.wsServerUri)
	if err != nil {
		criticalf("invalid websocket server: %s: %v", w.wsServerUri, err)
		return -1
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "ws" && scheme != "wss" {
		criticalf("invalid websocket scheme: %s", w.wsServerUri)
		return -1
	}

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	if scheme == "wss" {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	conn, _, err := dialer.Dial(parsed.String(), nil)
	if err != nil {
		criticalf("websocket connect failed: %v", err)
		return -1
	}

	w.writeMu.Lock()
	w.ws = conn
	w.writeMu.Unlock()
	w.timestamp.Store(bootTime())
	w.pingMessage = fmt.Sprintf("candy::%s::%s::%s", candySystem(), CANDY_VERSION, w.hostName())
	debugf("client info: %s", w.pingMessage)

	readTimeout := 45 * time.Second
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetPingHandler(func(appData string) error {
		w.timestamp.Store(bootTime())
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		w.writeMu.Lock()
		defer w.writeMu.Unlock()
		if w.ws != conn {
			return nil
		}
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
	})
	conn.SetPongHandler(func(_ string) error {
		w.timestamp.Store(bootTime())
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		return nil
	})

	return 0
}

func (w *WebSocketClient) disconnect() int {
	if w.ws == nil {
		return 0
	}
	w.writeMu.Lock()
	conn := w.ws
	w.ws = nil
	w.writeMu.Unlock()
	if conn == nil {
		return 0
	}
	if err := conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second)); err != nil && !errors.Is(err, net.ErrClosed) {
		debugf("websocket disconnect write close failed: %v", err)
	}
	if err := conn.Close(); err != nil {
		debugf("websocket disconnect failed: %v", err)
	}
	return 0
}

func (w *WebSocketClient) getClient() *Client {
	return w.client
}
