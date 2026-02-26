//go:build !windows

package common

func isIgnorableUDPReadError(err error) bool {
	return false
}
