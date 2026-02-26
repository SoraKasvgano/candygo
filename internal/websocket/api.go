package websocket

func (w *WebSocketClient) SetName(name string) int {
	return w.setName(name)
}

func (w *WebSocketClient) SetPassword(password string) int {
	return w.setPassword(password)
}

func (w *WebSocketClient) SetWsServerURI(uri string) int {
	return w.setWsServerUri(uri)
}

func (w *WebSocketClient) SetExptTunAddress(cidr string) int {
	return w.setExptTunAddress(cidr)
}

func (w *WebSocketClient) SetAddress(cidr string) int {
	return w.setAddress(cidr)
}

func (w *WebSocketClient) SetVirtualMac(vmac string) int {
	return w.setVirtualMac(vmac)
}

func (w *WebSocketClient) SetTunUpdateCallback(callback func(string) int) int {
	return w.setTunUpdateCallback(callback)
}

func (w *WebSocketClient) GetTunCidr() string {
	return w.getTunCidr()
}

func (w *WebSocketClient) Run(client runtimeClient) int {
	return w.run(wrapClient(client))
}

func (w *WebSocketClient) Wait() int {
	return w.wait()
}

func (ws *WebSocketServer) SetWebSocket(uri string) int {
	return ws.setWebSocket(uri)
}

func (ws *WebSocketServer) SetPassword(password string) int {
	return ws.setPassword(password)
}

func (ws *WebSocketServer) SetDHCP(cidr string) int {
	return ws.setDHCP(cidr)
}

func (ws *WebSocketServer) SetSdwan(sdwan string) int {
	return ws.setSdwan(sdwan)
}

func (ws *WebSocketServer) Run() int {
	return ws.run()
}

func (ws *WebSocketServer) Shutdown() int {
	return ws.shutdown()
}
