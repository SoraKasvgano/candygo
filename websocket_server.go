package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type WsCtx struct {
	ws     *websocket.Conn
	buffer []byte
	status int
	ip     IP4
	vmac   string
	mu     sync.Mutex
}

func (ctx *WsCtx) sendFrame(frame []byte) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.ws == nil {
		ctx.status = -1
		return
	}
	if err := ctx.ws.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		ctx.status = -1
		debugf("send websocket frame failed: %v", err)
	}
}

type SysRoute struct {
	dev  Address
	dst  Address
	next IP4
}

type WebSocketServer struct {
	host     string
	port     uint16
	path     string
	password string
	dhcp     Address
	routes   []SysRoute

	ipCtxMap   map[IP4]*WsCtx
	ipCtxMutex sync.RWMutex

	running atomic.Bool
	server  *http.Server
}

func (ws *WebSocketServer) ensureMaps() {
	if ws.ipCtxMap == nil {
		ws.ipCtxMap = make(map[IP4]*WsCtx)
	}
}

func (ws *WebSocketServer) setWebSocket(uri string) int {
	parsed, err := url.Parse(uri)
	if err != nil {
		criticalf("invalid websocket uri: %s: %v", uri, err)
		return -1
	}
	if parsed.Scheme != "ws" {
		criticalf("websocket server only support ws")
		return -1
	}
	ws.host = parsed.Hostname()
	if ws.host == "" {
		ws.host = "0.0.0.0"
	}
	port := parsed.Port()
	if port == "" {
		ws.port = 80
	} else {
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			criticalf("invalid websocket port: %s", port)
			return -1
		}
		ws.port = uint16(p)
	}
	if parsed.Path == "" {
		ws.path = "/"
	} else {
		ws.path = parsed.Path
	}
	return 0
}

func (ws *WebSocketServer) setPassword(password string) int {
	ws.password = password
	return 0
}

func (ws *WebSocketServer) setDHCP(cidr string) int {
	if strings.TrimSpace(cidr) == "" {
		return 0
	}
	return ws.dhcp.fromCidr(cidr)
}

func (ws *WebSocketServer) setSdwan(sdwan string) int {
	if strings.TrimSpace(sdwan) == "" {
		return 0
	}
	routes := strings.Split(sdwan, ";")
	for _, route := range routes {
		route = strings.TrimSpace(route)
		if route == "" {
			continue
		}
		parts := strings.Split(route, ",")
		if len(parts) != 3 {
			criticalf("invalid route format: %s", route)
			return -1
		}
		var rt SysRoute
		if rt.dev.fromCidr(parts[0]) != 0 || rt.dev.Host() != rt.dev.Net() {
			criticalf("invalid route device: %s", route)
			return -1
		}
		if rt.dst.fromCidr(parts[1]) != 0 || rt.dst.Host() != rt.dst.Net() {
			criticalf("invalid route dest: %s", route)
			return -1
		}
		if rt.next.fromString(parts[2]) != 0 {
			criticalf("invalid route nexthop: %s", route)
			return -1
		}
		infof("route: dev=%s dst=%s next=%s", rt.dev.toCidr(), rt.dst.toCidr(), rt.next.toString())
		ws.routes = append(ws.routes, rt)
	}
	return 0
}

func (ws *WebSocketServer) run() int {
	return ws.listen()
}

func (ws *WebSocketServer) shutdown() int {
	ws.running.Store(false)
	if ws.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = ws.server.Shutdown(ctx)
		cancel()
	}
	ws.routes = nil
	return 0
}

func (ws *WebSocketServer) handleMsg(ctx *WsCtx) {
	if len(ctx.buffer) == 0 {
		return
	}
	switch ctx.buffer[0] {
	case WsMsgKindAUTH:
		ws.handleAuthMsg(ctx)
	case WsMsgKindFORWARD:
		ws.handleForwardMsg(ctx)
	case WsMsgKindEXPTTUN:
		ws.handleExptTunMsg(ctx)
	case WsMsgKindUDP4CONN:
		ws.handleUdp4ConnMsg(ctx)
	case WsMsgKindVMAC:
		ws.handleVMacMsg(ctx)
	case WsMsgKindDISCOVERY:
		ws.handleDiscoveryMsg(ctx)
	case WsMsgKindGENERAL:
		ws.HandleGeneralMsg(ctx)
	}
}

func (ws *WebSocketServer) handleAuthMsg(ctx *WsCtx) {
	header, ok := decodeWsMsgAuth(ctx.buffer)
	if !ok {
		warnf("invalid auth message: len %d", len(ctx.buffer))
		ctx.status = -1
		return
	}
	if !header.check(ws.password) {
		warnf("auth header check failed")
		ctx.status = -1
		return
	}
	ctx.ip = header.ip

	ws.ipCtxMutex.Lock()
	oldCtx, exists := ws.ipCtxMap[header.ip]
	if exists {
		oldCtx.status = -1
		_ = oldCtx.ws.Close()
		infof("reconnect: %s", oldCtx.ip.toString())
	} else {
		infof("connect: %s", ctx.ip.toString())
	}
	ws.ipCtxMap[header.ip] = ctx
	ws.ipCtxMutex.Unlock()

	ws.updateSysRoute(ctx)
}

func (ws *WebSocketServer) handleForwardMsg(ctx *WsCtx) {
	if ctx.ip.empty() {
		debugf("unauthorized forward websocket client")
		ctx.status = -1
		return
	}
	if len(ctx.buffer) < 1+ip4HeaderSize {
		debugf("invalid forward message: len %d", len(ctx.buffer))
		ctx.status = -1
		return
	}
	daddr := ip4HeaderDAddr(ctx.buffer[1:])

	ws.ipCtxMutex.RLock()
	target, ok := ws.ipCtxMap[daddr]
	ws.ipCtxMutex.RUnlock()
	if ok {
		target.sendFrame(ctx.buffer)
		return
	}

	broadcast := ws.isBroadcastDest(daddr)
	if broadcast {
		ws.ipCtxMutex.RLock()
		for _, c := range ws.ipCtxMap {
			if c.ip != ctx.ip {
				c.sendFrame(ctx.buffer)
			}
		}
		ws.ipCtxMutex.RUnlock()
		return
	}

	saddr := ip4HeaderSAddr(ctx.buffer[1:])
	debugf("forward failed: source %s dest %s", saddr.toString(), daddr.toString())
}

func (ws *WebSocketServer) isBroadcastDest(dest IP4) bool {
	if dest.and(newIP4("240.0.0.0")) == newIP4("224.0.0.0") {
		return true
	}
	if dest == newIP4("255.255.255.255") {
		return true
	}
	if ws.dhcp.empty() {
		return false
	}
	if ws.dhcp.Mask().and(dest) != ws.dhcp.Net() {
		return false
	}
	if !dest.and(ws.dhcp.Mask().not()).xor(ws.dhcp.Mask()).not().empty() {
		return false
	}
	return true
}

func (ws *WebSocketServer) handleExptTunMsg(ctx *WsCtx) {
	header, ok := decodeWsMsgExptTun(ctx.buffer)
	if !ok {
		warnf("invalid dynamic address message: len %d", len(ctx.buffer))
		ctx.status = -1
		return
	}
	if !header.check(ws.password) {
		warnf("dynamic address header check failed")
		ctx.status = -1
		return
	}
	if ws.dhcp.empty() {
		warnf("unable to allocate dynamic address")
		ctx.status = -1
		return
	}
	var exptTun Address
	if exptTun.fromCidr(header.cidr) != 0 {
		warnf("dynamic address header cidr invalid")
		ctx.status = -1
		return
	}

	direct := func() bool {
		if ws.dhcp.Net() != exptTun.Net() {
			return false
		}
		ws.ipCtxMutex.RLock()
		oldCtx, exists := ws.ipCtxMap[exptTun.Host()]
		ws.ipCtxMutex.RUnlock()
		if !exists {
			return true
		}
		return ctx.vmac == oldCtx.vmac
	}()

	if !direct {
		exptTun = ws.dhcp
		ws.ipCtxMutex.RLock()
		for {
			exptTun = exptTun.Next()
			if exptTun.Host() == ws.dhcp.Host() {
				ws.ipCtxMutex.RUnlock()
				warnf("all addresses in the network are assigned")
				ctx.status = -1
				return
			}
			_, exists := ws.ipCtxMap[exptTun.Host()]
			if !(!exptTun.isValid() && exists) {
				break
			}
		}
		ws.ipCtxMutex.RUnlock()
		ws.dhcp = exptTun
	}

	header.timestamp = unixTime()
	header.cidr = exptTun.toCidr()
	header.updateHash(ws.password)
	ctx.sendFrame(header.encode())
}

func (ws *WebSocketServer) handleUdp4ConnMsg(ctx *WsCtx) {
	if ctx.ip.empty() {
		debugf("unauthorized peer websocket client")
		ctx.status = -1
		return
	}
	header, ok := decodeWsMsgConn(ctx.buffer)
	if !ok {
		warnf("invalid peer conn message: len %d", len(ctx.buffer))
		ctx.status = -1
		return
	}
	if ctx.ip != header.src {
		debugf("peer source address does not match: auth %s source %s", ctx.ip.toString(), header.src.toString())
		ctx.status = -1
		return
	}
	ws.ipCtxMutex.RLock()
	target := ws.ipCtxMap[header.dst]
	ws.ipCtxMutex.RUnlock()
	if target == nil {
		debugf("peer dest address not logged in: source %s dst %s", header.src.toString(), header.dst.toString())
		return
	}
	target.sendFrame(ctx.buffer)
}

func (ws *WebSocketServer) handleVMacMsg(ctx *WsCtx) {
	header, ok := decodeWsMsgVMac(ctx.buffer)
	if !ok {
		warnf("invalid vmac message: len %d", len(ctx.buffer))
		ctx.status = -1
		return
	}
	if !header.check(ws.password) {
		warnf("vmac message check failed")
		ctx.status = -1
		return
	}
	ctx.vmac = string(header.vmac[:])
}

func (ws *WebSocketServer) handleDiscoveryMsg(ctx *WsCtx) {
	if ctx.ip.empty() {
		debugf("unauthorized discovery websocket client")
		ctx.status = -1
		return
	}
	header, ok := decodeWsMsgDiscovery(ctx.buffer)
	if !ok {
		debugf("invalid discovery message: len %d", len(ctx.buffer))
		ctx.status = -1
		return
	}
	if ctx.ip != header.src {
		debugf("discovery source address does not match: auth %s source %s", ctx.ip.toString(), header.src.toString())
		ctx.status = -1
		return
	}

	ws.ipCtxMutex.RLock()
	defer ws.ipCtxMutex.RUnlock()
	if header.dst == newIP4("255.255.255.255") {
		for ip, c := range ws.ipCtxMap {
			if ip != header.src {
				c.sendFrame(ctx.buffer)
			}
		}
		return
	}
	if c := ws.ipCtxMap[header.dst]; c != nil {
		c.sendFrame(ctx.buffer)
	}
}

func (ws *WebSocketServer) HandleGeneralMsg(ctx *WsCtx) {
	if ctx.ip.empty() {
		debugf("unauthorized general websocket client")
		ctx.status = -1
		return
	}
	header, ok := decodeWsMsgGeneral(ctx.buffer)
	if !ok {
		debugf("invalid general message: len %d", len(ctx.buffer))
		ctx.status = -1
		return
	}
	if ctx.ip != header.src {
		debugf("general source address does not match: auth %s source %s", ctx.ip.toString(), header.src.toString())
		ctx.status = -1
		return
	}

	ws.ipCtxMutex.RLock()
	defer ws.ipCtxMutex.RUnlock()
	if header.dst == newIP4("255.255.255.255") {
		for ip, c := range ws.ipCtxMap {
			if ip != header.src {
				c.sendFrame(ctx.buffer)
			}
		}
		return
	}
	if c := ws.ipCtxMap[header.dst]; c != nil {
		c.sendFrame(ctx.buffer)
	}
}

func (ws *WebSocketServer) updateSysRoute(ctx *WsCtx) {
	entries := make([]SysRouteEntry, 0, 101)
	flush := func() {
		if len(entries) == 0 {
			return
		}
		ctx.sendFrame(encodeWsMsgSysRoute(entries))
		entries = entries[:0]
	}

	for _, rt := range ws.routes {
		if rt.dev.Mask().and(ctx.ip) == rt.dev.Host() {
			entries = append(entries, SysRouteEntry{dst: rt.dst.Net(), mask: rt.dst.Mask(), nexthop: rt.next})
		}
		if len(entries) > 100 {
			flush()
		}
	}
	flush()
}

func (ws *WebSocketServer) listen() int {
	ws.ensureMaps()
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ws.handleWebsocket(conn)
	}
	mux.HandleFunc("/", handler)
	if ws.path != "" && ws.path != "/" {
		mux.HandleFunc(ws.path, handler)
	}

	addr := net.JoinHostPort(ws.host, strconv.Itoa(int(ws.port)))
	ws.server = &http.Server{Addr: addr, Handler: mux}
	ws.running.Store(true)
	go func() {
		if err := ws.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			criticalf("listen failed: %v", err)
		}
	}()
	infof("listen on: %s:%d", ws.host, ws.port)
	return 0
}

func (ws *WebSocketServer) handleWebsocket(conn *websocket.Conn) {
	ctx := &WsCtx{ws: conn, status: 0}
	defer func() {
		ws.ipCtxMutex.Lock()
		if old, ok := ws.ipCtxMap[ctx.ip]; ok && old == ctx {
			delete(ws.ipCtxMap, ctx.ip)
			infof("disconnect: %s", ctx.ip.toString())
		}
		ws.ipCtxMutex.Unlock()
		_ = conn.Close()
	}()

	conn.SetReadLimit(4 * 1024)
	for ws.running.Load() && ctx.status == 0 {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		messageType, buffer, err := conn.ReadMessage()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				break
			}
			debugf("handle websocket failed: %v", err)
			break
		}
		if messageType != websocket.BinaryMessage || len(buffer) == 0 {
			continue
		}
		ctx.buffer = append([]byte{}, buffer...)
		ws.handleMsg(ctx)
	}
}
