//go:build windows

package common

import (
	"errors"
	"net"
	"os"
	"syscall"
)

func isIgnorableUDPReadError(err error) bool {
	// Keep parity with C++: ignore Windows UDP connection reset notifications.
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	var sysErr *os.SyscallError
	if !errors.As(opErr.Err, &sysErr) {
		return false
	}
	errno, ok := sysErr.Err.(syscall.Errno)
	return ok && errno == syscall.WSAECONNRESET
}
