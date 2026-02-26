package tun

func (t *Tun) SetName(name string) int {
	return t.setName(name)
}

func (t *Tun) SetMTU(mtu int) int {
	return t.setMTU(mtu)
}

func (t *Tun) Run(client runtimeClient) int {
	return t.run(wrapClient(client))
}

func (t *Tun) Wait() int {
	return t.wait()
}

func (t *Tun) GetIP() IP4 {
	return t.getIP()
}

func (t *Tun) Down() int {
	return t.down()
}
