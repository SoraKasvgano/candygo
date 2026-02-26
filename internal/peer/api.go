package peer

func (p *PeerManager) SetPassword(password string) int {
	return p.setPassword(password)
}

func (p *PeerManager) SetStun(stun string) int {
	return p.setStun(stun)
}

func (p *PeerManager) SetDiscoveryInterval(interval int) int {
	return p.setDiscoveryInterval(interval)
}

func (p *PeerManager) SetRouteCost(cost int) int {
	return p.setRouteCost(cost)
}

func (p *PeerManager) SetPort(port int) int {
	return p.setPort(port)
}

func (p *PeerManager) SetLocalhost(ip string) int {
	return p.setLocalhost(ip)
}

func (p *PeerManager) Run(client runtimeClient) int {
	return p.run(wrapClient(client))
}

func (p *PeerManager) Wait() int {
	return p.wait()
}
