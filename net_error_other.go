//go:build !windows

package main

func isIgnorableUDPReadError(err error) bool {
	return false
}
