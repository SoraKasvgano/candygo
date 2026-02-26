//go:build windows

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	mibIPProtoNetMgmt      = 3
	mibIPRouteTypeIndirect = 4
	mibIPRouteMetricUnused = 0xFFFFFFFF
	winInfinite            = 0xFFFFFFFF
)

type mibIPForwardRow struct {
	DwForwardDest      uint32
	DwForwardMask      uint32
	DwForwardPolicy    uint32
	DwForwardNextHop   uint32
	DwForwardIfIndex   uint32
	DwForwardType      uint32
	DwForwardProto     uint32
	DwForwardAge       uint32
	DwForwardNextHopAS uint32
	DwForwardMetric1   uint32
	DwForwardMetric2   uint32
	DwForwardMetric3   uint32
	DwForwardMetric4   uint32
	DwForwardMetric5   uint32
}

var (
	iphlpapiDLL = windows.NewLazySystemDLL("iphlpapi.dll")

	procInitializeUnicastIpAddressEntry = iphlpapiDLL.NewProc("InitializeUnicastIpAddressEntry")
	procCreateUnicastIpAddressEntry     = iphlpapiDLL.NewProc("CreateUnicastIpAddressEntry")
	procInitializeIpInterfaceEntry      = iphlpapiDLL.NewProc("InitializeIpInterfaceEntry")
	procGetIpInterfaceEntry             = iphlpapiDLL.NewProc("GetIpInterfaceEntry")
	procSetIpInterfaceEntry             = iphlpapiDLL.NewProc("SetIpInterfaceEntry")
	procCreateIpForwardEntry            = iphlpapiDLL.NewProc("CreateIpForwardEntry")
	procDeleteIpForwardEntry            = iphlpapiDLL.NewProc("DeleteIpForwardEntry")
)

func (t *osTun) configureAddressWindows() error {
	if err := t.refreshWinIfIndex(); err != nil {
		return err
	}

	var row windows.MibUnicastIpAddressRow
	initializeUnicastIpAddressEntry(&row)
	row.InterfaceIndex = t.ifindex
	row.OnLinkPrefixLength = uint8(t.prefix)
	row.DadState = windows.IpDadStatePreferred

	addr := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
	addr.Family = windows.AF_INET
	ipBytes := t.ip.Bytes()
	copy(addr.Addr[:], ipBytes)

	if err := createUnicastIpAddressEntry(&row); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("create unicast ip address entry failed: %w", err)
	}
	return nil
}

func (t *osTun) configureMTUWindows() error {
	if err := t.refreshWinIfIndex(); err != nil {
		return err
	}

	var iface windows.MibIpInterfaceRow
	initializeIpInterfaceEntry(&iface)
	iface.Family = windows.AF_INET
	iface.InterfaceIndex = t.ifindex
	if err := getIpInterfaceEntry(&iface); err != nil {
		return fmt.Errorf("get ip interface entry failed: %w", err)
	}

	iface.SitePrefixLength = 0
	iface.NlMtu = uint32(t.mtu)
	if err := setIpInterfaceEntry(&iface); err != nil {
		return fmt.Errorf("set ip interface entry failed: %w", err)
	}
	return nil
}

func (t *osTun) setWinRoute(dst, mask, nexthop IP4) error {
	if err := t.refreshWinIfIndex(); err != nil {
		return err
	}

	route := buildWinRouteRow(t.ifindex, dst, mask, nexthop)
	if err := createIpForwardEntry(&route); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return err
	}
	return nil
}

func (t *osTun) deleteWinRoute(dst, mask, nexthop IP4) error {
	if err := t.refreshWinIfIndex(); err != nil {
		return err
	}

	route := buildWinRouteRow(t.ifindex, dst, mask, nexthop)
	err := deleteIpForwardEntry(&route)
	if err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return err
	}
	return nil
}

func (t *osTun) refreshWinIfIndex() error {
	if t.ifindex != 0 {
		return nil
	}
	iface, err := net.InterfaceByName(t.ifname)
	if err != nil {
		return fmt.Errorf("get interface by name failed: %w", err)
	}
	t.ifindex = uint32(iface.Index)
	return nil
}

func buildWinRouteRow(ifindex uint32, dst, mask, nexthop IP4) mibIPForwardRow {
	return mibIPForwardRow{
		DwForwardDest:      ip4ToWinU32(dst),
		DwForwardMask:      ip4ToWinU32(mask),
		DwForwardNextHop:   ip4ToWinU32(nexthop),
		DwForwardIfIndex:   ifindex,
		DwForwardType:      mibIPRouteTypeIndirect,
		DwForwardProto:     mibIPProtoNetMgmt,
		DwForwardAge:       winInfinite,
		DwForwardNextHopAS: 0,
		DwForwardMetric1:   mibIPRouteTypeIndirect + 1,
		DwForwardMetric2:   mibIPRouteMetricUnused,
		DwForwardMetric3:   mibIPRouteMetricUnused,
		DwForwardMetric4:   mibIPRouteMetricUnused,
		DwForwardMetric5:   mibIPRouteMetricUnused,
	}
}

func ip4ToWinU32(ip IP4) uint32 {
	return binary.LittleEndian.Uint32(ip.Bytes())
}

func initializeUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) {
	if err := procInitializeUnicastIpAddressEntry.Find(); err == nil {
		_, _, _ = procInitializeUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	}
}

func initializeIpInterfaceEntry(row *windows.MibIpInterfaceRow) {
	if err := procInitializeIpInterfaceEntry.Find(); err == nil {
		_, _, _ = procInitializeIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	}
}

func createUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) error {
	return callWinStatus(procCreateUnicastIpAddressEntry, uintptr(unsafe.Pointer(row)))
}

func getIpInterfaceEntry(row *windows.MibIpInterfaceRow) error {
	return callWinStatus(procGetIpInterfaceEntry, uintptr(unsafe.Pointer(row)))
}

func setIpInterfaceEntry(row *windows.MibIpInterfaceRow) error {
	return callWinStatus(procSetIpInterfaceEntry, uintptr(unsafe.Pointer(row)))
}

func createIpForwardEntry(row *mibIPForwardRow) error {
	return callWinStatus(procCreateIpForwardEntry, uintptr(unsafe.Pointer(row)))
}

func deleteIpForwardEntry(row *mibIPForwardRow) error {
	return callWinStatus(procDeleteIpForwardEntry, uintptr(unsafe.Pointer(row)))
}

func callWinStatus(proc *windows.LazyProc, arg uintptr) error {
	if err := proc.Find(); err != nil {
		return err
	}
	ret, _, _ := proc.Call(arg)
	if ret != 0 {
		return syscall.Errno(ret)
	}
	return nil
}
