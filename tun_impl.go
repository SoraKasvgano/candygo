package main

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type osTun struct {
	name    string
	ifname  string
	ifindex uint32
	ip      IP4
	mask    IP4
	prefix  uint32
	mtu     int
	timeout time.Duration

	devMu   sync.Mutex
	dev     wgtun.Device
	routes  []SysRouteEntry
	rtMutex sync.Mutex
}

func (t *osTun) setName(name string) int {
	if runtime.GOOS == "windows" {
		if name == "" {
			t.name = "candy"
		} else {
			t.name = name
		}
		return 0
	}
	if name == "" {
		t.name = "candy"
	} else {
		t.name = "candy-" + name
	}
	return 0
}

func (t *osTun) setIP(ip IP4) int {
	t.ip = ip
	return 0
}

func (t *osTun) getIP() IP4 {
	return t.ip
}

func (t *osTun) setMask(mask IP4) int {
	t.mask = mask
	return 0
}

func (t *osTun) setPrefix(prefix int) int {
	t.prefix = uint32(prefix)
	return 0
}

func (t *osTun) setMTU(mtu int) int {
	if mtu <= 0 {
		return -1
	}
	t.mtu = mtu
	return 0
}

func (t *osTun) up() int {
	t.devMu.Lock()
	if t.dev != nil {
		t.devMu.Unlock()
		return 0
	}
	t.devMu.Unlock()
	if t.mtu <= 0 {
		t.mtu = 1400
	}
	dev, err := wgtun.CreateTUN(t.name, t.mtu)
	if err != nil {
		criticalf("create tun failed: %v", err)
		if runtime.GOOS == "windows" && strings.Contains(strings.ToLower(err.Error()), "wintun.dll") {
			criticalf("wintun.dll not found. Put amd64 wintun.dll next to candygo.exe or in C:\\Windows\\System32")
		}
		return -1
	}
	t.devMu.Lock()
	t.dev = dev
	t.devMu.Unlock()
	ifname, err := dev.Name()
	if err != nil {
		criticalf("get tun name failed: %v", err)
		_ = dev.Close()
		t.devMu.Lock()
		t.dev = nil
		t.devMu.Unlock()
		return -1
	}
	t.ifname = ifname
	debugf("created tun interface: %s", t.ifname)

	if t.configureAddress() != nil {
		_ = t.down()
		return -1
	}
	if t.configureMTU() != nil {
		_ = t.down()
		return -1
	}
	if t.configureUp() != nil {
		_ = t.down()
		return -1
	}

	if runtime.GOOS == "darwin" {
		netAddr := t.ip.and(t.mask)
		if t.setSysRtTable(netAddr, t.mask, t.ip) != 0 {
			_ = t.down()
			return -1
		}
	}

	return 0
}

func (t *osTun) down() int {
	t.devMu.Lock()
	dev := t.dev
	t.dev = nil
	t.devMu.Unlock()
	t.ifindex = 0
	if dev == nil {
		return 0
	}
	t.cleanupRoutes()
	_ = t.configureDown()
	err := dev.Close()
	if err != nil {
		warnf("close tun failed: %v", err)
		return -1
	}
	return 0
}

func (t *osTun) read() ([]byte, error) {
	t.devMu.Lock()
	dev := t.dev
	t.devMu.Unlock()
	if dev == nil {
		return nil, errors.New("tun device is closed")
	}
	buf := make([]byte, t.mtu+64)
	bufs := [][]byte{buf}
	sizes := make([]int, 1)
	n, err := dev.Read(bufs, sizes, 0)
	if err != nil {
		return nil, err
	}
	if n <= 0 || sizes[0] <= 0 {
		return nil, nil
	}
	out := make([]byte, sizes[0])
	copy(out, buf[:sizes[0]])
	return out, nil
}

func (t *osTun) write(buffer []byte) error {
	t.devMu.Lock()
	dev := t.dev
	t.devMu.Unlock()
	if dev == nil {
		return errors.New("tun device is closed")
	}
	_, err := dev.Write([][]byte{buffer}, 0)
	return err
}

func (t *osTun) setSysRtTable(dst IP4, mask IP4, nexthop IP4) int {
	t.rtMutex.Lock()
	t.routes = append(t.routes, SysRouteEntry{dst: dst, mask: mask, nexthop: nexthop})
	t.rtMutex.Unlock()

	dstCIDR := fmt.Sprintf("%s/%d", dst.toString(), mask.toPrefix())
	nhStr := nexthop.toString()

	switch runtime.GOOS {
	case "linux":
		if err := runCmd("ip", "route", "replace", dstCIDR, "via", nhStr, "dev", t.ifname); err != nil {
			errorf("set route failed: %v", err)
			return -1
		}
	case "darwin":
		if err := runCmd("route", "-n", "add", "-net", dstCIDR, nhStr); err != nil {
			_ = runCmd("route", "-n", "change", "-net", dstCIDR, nhStr)
		}
	case "windows":
		if err := t.setWinRoute(dst, mask, nexthop); err != nil {
			errorf("add route failed: %v", err)
			return -1
		}
	default:
		warnf("route setting not supported on %s", runtime.GOOS)
	}
	return 0
}

func (t *osTun) configureAddress() error {
	ipStr := t.ip.toString()
	prefix := t.mask.toPrefix()
	switch runtime.GOOS {
	case "linux":
		return runCmd("ip", "addr", "replace", fmt.Sprintf("%s/%d", ipStr, prefix), "dev", t.ifname)
	case "darwin":
		return runCmd("ifconfig", t.ifname, "inet", ipStr, ipStr, "netmask", t.mask.toString())
	case "windows":
		return t.configureAddressWindows()
	default:
		return fmt.Errorf("unsupported os: %s", runtime.GOOS)
	}
}

func (t *osTun) configureMTU() error {
	switch runtime.GOOS {
	case "linux":
		return runCmd("ip", "link", "set", "dev", t.ifname, "mtu", strconv.Itoa(t.mtu))
	case "darwin":
		return runCmd("ifconfig", t.ifname, "mtu", strconv.Itoa(t.mtu))
	case "windows":
		return t.configureMTUWindows()
	default:
		return nil
	}
}

func (t *osTun) configureUp() error {
	switch runtime.GOOS {
	case "linux":
		return runCmd("ip", "link", "set", "dev", t.ifname, "up")
	case "darwin":
		return runCmd("ifconfig", t.ifname, "up")
	case "windows":
		return nil
	default:
		return nil
	}
}

func (t *osTun) configureDown() error {
	switch runtime.GOOS {
	case "linux":
		return runCmd("ip", "link", "set", "dev", t.ifname, "down")
	case "darwin":
		return runCmd("ifconfig", t.ifname, "down")
	case "windows":
		return nil
	default:
		return nil
	}
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %v (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (t *osTun) cleanupRoutes() {
	t.rtMutex.Lock()
	routes := append([]SysRouteEntry(nil), t.routes...)
	t.routes = nil
	t.rtMutex.Unlock()

	if len(routes) == 0 {
		return
	}

	switch runtime.GOOS {
	case "linux":
		for _, rt := range routes {
			dstCIDR := fmt.Sprintf("%s/%d", rt.dst.toString(), rt.mask.toPrefix())
			_ = runCmd("ip", "route", "del", dstCIDR, "via", rt.nexthop.toString(), "dev", t.ifname)
		}
	case "darwin":
		for _, rt := range routes {
			dstCIDR := fmt.Sprintf("%s/%d", rt.dst.toString(), rt.mask.toPrefix())
			_ = runCmd("route", "-n", "delete", "-net", dstCIDR, rt.nexthop.toString())
		}
	case "windows":
		for _, rt := range routes {
			if err := t.deleteWinRoute(rt.dst, rt.mask, rt.nexthop); err != nil {
				warnf("delete route failed: %v", err)
			}
		}
	}
}
