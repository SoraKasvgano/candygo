package tun

import (
	"bytes"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"candygo/internal/common"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type testRuntimeClient struct {
	running   atomic.Bool
	tunQueue  MsgQueue
	peerQueue MsgQueue
}

func newTestRuntimeClient() *testRuntimeClient {
	c := &testRuntimeClient{
		tunQueue:  common.NewMsgQueue(),
		peerQueue: common.NewMsgQueue(),
	}
	c.running.Store(true)
	return c
}

func (c *testRuntimeClient) IsRunning() bool {
	return c.running.Load()
}

func (c *testRuntimeClient) Shutdown() {
	c.running.Store(false)
}

func (c *testRuntimeClient) GetTunMsgQueue() *common.MsgQueue {
	return &c.tunQueue
}

func (c *testRuntimeClient) GetPeerMsgQueue() *common.MsgQueue {
	return &c.peerQueue
}

type testDevice struct {
	readPacket []byte
	writes     [][]byte
	events     chan wgtun.Event
}

func newTestDevice(packet []byte) *testDevice {
	return &testDevice{
		readPacket: append([]byte(nil), packet...),
		events:     make(chan wgtun.Event),
	}
}

func (d *testDevice) File() *os.File {
	return nil
}

func (d *testDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(d.readPacket) == 0 {
		return 0, nil
	}
	n := copy(bufs[0][offset:], d.readPacket)
	sizes[0] = n
	d.readPacket = nil
	return 1, nil
}

func (d *testDevice) Write(bufs [][]byte, offset int) (int, error) {
	for _, buffer := range bufs {
		d.writes = append(d.writes, append([]byte(nil), buffer[offset:]...))
	}
	return len(bufs), nil
}

func (d *testDevice) MTU() (int, error) {
	return 1400, nil
}

func (d *testDevice) Name() (string, error) {
	return "test-tun", nil
}

func (d *testDevice) Events() <-chan wgtun.Event {
	return d.events
}

func (d *testDevice) Close() error {
	return nil
}

func (d *testDevice) BatchSize() int {
	return 1
}

func mustIP4(t *testing.T, value string) IP4 {
	t.Helper()
	var ip IP4
	if ip.FromString(value) != 0 {
		t.Fatalf("invalid test IPv4 address %q", value)
	}
	return ip
}

func ipv4Packet(t *testing.T, src, dst string) []byte {
	t.Helper()
	packet := make([]byte, ip4HeaderSize)
	packet[0] = 0x45
	common.Ip4HeaderSetSAddr(packet, mustIP4(t, src))
	common.Ip4HeaderSetDAddr(packet, mustIP4(t, dst))
	return packet
}

func newPacketTestTun(t *testing.T, packet []byte) (*Tun, *testRuntimeClient, *testDevice) {
	t.Helper()
	device := newTestDevice(packet)
	runtimeClient := newTestRuntimeClient()
	tun := &Tun{
		impl:   &osTun{mtu: 1400, dev: device},
		client: wrapClient(runtimeClient),
	}
	if tun.setAddress("192.168.202.10/24") != 0 {
		t.Fatal("setAddress failed")
	}
	return tun, runtimeClient, device
}

func TestInvalidSrcDstMatchesCandyRules(t *testing.T) {
	tun := &Tun{
		ip:   mustIP4(t, "192.168.202.10"),
		mask: mustIP4(t, "255.255.255.0"),
	}

	tests := []struct {
		name    string
		src     string
		dst     string
		invalid bool
	}{
		{name: "same subnet", src: "192.168.202.20", dst: "192.168.202.30"},
		{name: "directed broadcast", src: "192.168.202.20", dst: "192.168.202.255"},
		{name: "source outside subnet", src: "10.0.0.1", dst: "192.168.202.30", invalid: true},
		{name: "destination outside subnet", src: "192.168.202.20", dst: "8.8.8.8", invalid: true},
		{name: "limited broadcast exception", src: "0.0.0.0", dst: "255.255.255.255"},
		{name: "multicast lower bound", src: "10.0.0.1", dst: "224.0.0.0"},
		{name: "multicast upper bound", src: "10.0.0.1", dst: "239.255.255.255"},
		{name: "outside multicast range", src: "10.0.0.1", dst: "240.0.0.1", invalid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tun.invalidSrcDst(mustIP4(t, tt.src), mustIP4(t, tt.dst))
			if got != tt.invalid {
				t.Fatalf("invalidSrcDst(%s, %s) = %t, want %t", tt.src, tt.dst, got, tt.invalid)
			}
		})
	}
}

func TestHandleTunDeviceWritesLocalDestinationBeforeRouting(t *testing.T) {
	packet := ipv4Packet(t, "192.168.202.20", "192.168.202.10")
	tun, _, device := newPacketTestTun(t, packet)
	tun.sysRtTable = []SysRouteEntry{{
		Dst:     mustIP4(t, "0.0.0.0"),
		Mask:    mustIP4(t, "0.0.0.0"),
		Nexthop: mustIP4(t, "192.168.202.2"),
	}}

	if tun.handleTunDevice() != 0 {
		t.Fatal("handleTunDevice failed")
	}
	if len(device.writes) != 1 {
		t.Fatalf("local packet writes = %d, want 1", len(device.writes))
	}
	if !bytes.Equal(device.writes[0], packet) {
		t.Fatal("local packet was modified before being written back to TUN")
	}
}

func TestHandleTunDeviceValidatesAfterRouteEncapsulation(t *testing.T) {
	packet := ipv4Packet(t, "192.168.202.20", "8.8.8.8")
	tun, runtimeClient, _ := newPacketTestTun(t, packet)
	nextHop := mustIP4(t, "192.168.202.2")
	tun.sysRtTable = []SysRouteEntry{{
		Dst:     mustIP4(t, "0.0.0.0"),
		Mask:    mustIP4(t, "0.0.0.0"),
		Nexthop: nextHop,
	}}

	if tun.handleTunDevice() != 0 {
		t.Fatal("handleTunDevice failed")
	}
	msg := runtimeClient.peerQueue.Read()
	if msg.Kind != PACKET {
		t.Fatalf("peer message kind = %d, want PACKET", msg.Kind)
	}
	if len(msg.Data) != len(packet)+ip4HeaderSize {
		t.Fatalf("encapsulated packet size = %d, want %d", len(msg.Data), len(packet)+ip4HeaderSize)
	}
	if got := ip4HeaderSAddr(msg.Data); got != tun.getIP() {
		t.Fatalf("outer source = %s, want %s", got.ToString(), tun.getIP().ToString())
	}
	if got := ip4HeaderDAddr(msg.Data); got != nextHop {
		t.Fatalf("outer destination = %s, want %s", got.ToString(), nextHop.ToString())
	}
	if !ip4HeaderIsIPIP(msg.Data) {
		t.Fatal("routed packet is not marked as IP-in-IP")
	}
}

func TestHandleTunDeviceDropsOutOfNetworkPacket(t *testing.T) {
	packet := ipv4Packet(t, "192.168.202.20", "8.8.8.8")
	tun, runtimeClient, device := newPacketTestTun(t, packet)

	if tun.handleTunDevice() != 0 {
		t.Fatal("handleTunDevice failed")
	}
	if len(device.writes) != 0 {
		t.Fatalf("dropped packet writes = %d, want 0", len(device.writes))
	}
	if msg := runtimeClient.peerQueue.Read(); msg.Kind != TIMEOUT {
		t.Fatalf("dropped packet produced peer message kind %d", msg.Kind)
	}
}

func TestWaitJoinsTunThreadStartedByMsgThread(t *testing.T) {
	tun := &Tun{}
	msgStarted := make(chan struct{})
	releaseMsg := make(chan struct{})
	tunStarted := make(chan struct{})
	releaseTun := make(chan struct{})

	tun.msgThread = newThread(func() {
		close(msgStarted)
		<-releaseMsg
		tun.tunThread = newThread(func() {
			close(tunStarted)
			<-releaseTun
		})
	})
	<-msgStarted

	waitDone := make(chan struct{})
	go func() {
		_ = tun.wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		t.Fatal("wait returned before the message thread was released")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseMsg)

	select {
	case <-tunStarted:
	case <-time.After(time.Second):
		t.Fatal("message thread did not start the TUN thread")
	}
	select {
	case <-waitDone:
		t.Fatal("wait returned before the late-started TUN thread exited")
	case <-time.After(20 * time.Millisecond):
	}

	close(releaseTun)
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("wait did not join the TUN thread")
	}
	if tun.msgThread != nil || tun.tunThread != nil {
		t.Fatal("wait did not clear joined thread handles")
	}
}
