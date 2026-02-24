//go:build !windows

package main

import "fmt"

func (t *osTun) configureAddressWindows() error {
	return fmt.Errorf("windows tun address configuration is only available on windows")
}

func (t *osTun) configureMTUWindows() error {
	return fmt.Errorf("windows tun mtu configuration is only available on windows")
}

func (t *osTun) setWinRoute(dst, mask, nexthop IP4) error {
	return fmt.Errorf("windows route configuration is only available on windows")
}

func (t *osTun) deleteWinRoute(dst, mask, nexthop IP4) error {
	return fmt.Errorf("windows route cleanup is only available on windows")
}
