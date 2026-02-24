package main

import (
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	CANDY_VERSION = "6.1.6-go"
	VMAC_SIZE     = 16
)

func candySystem() string {
	switch runtime.GOOS {
	case "linux":
		return "linux"
	case "darwin":
		return "macos"
	case "android":
		return "android"
	case "windows":
		return "windows"
	default:
		return "unknown"
	}
}

var (
	debugEnabled      atomic.Bool
	noTimestampOutput atomic.Bool
	logMutex          sync.Mutex
	stdLogOnce        sync.Once
)

func setDebug(enabled bool) {
	debugEnabled.Store(enabled)
}

func setNoTimestamp(enabled bool) {
	noTimestampOutput.Store(enabled)
}

func logf(level string, format string, args ...any) {
	logMutex.Lock()
	defer logMutex.Unlock()

	level = strings.ToLower(level)
	if noTimestampOutput.Load() {
		fmt.Printf("[%s] %s\n", level, fmt.Sprintf(format, args...))
		return
	}
	fmt.Printf("[%s] [%s] %s\n", getCurrentTimeWithMillis(), level, fmt.Sprintf(format, args...))
}

func debugf(format string, args ...any) {
	if debugEnabled.Load() {
		logf("debug", format, args...)
	}
}

func infof(format string, args ...any) {
	logf("info", format, args...)
}

func warnf(format string, args ...any) {
	logf("warn", format, args...)
}

func errorf(format string, args ...any) {
	logf("error", format, args...)
}

func criticalf(format string, args ...any) {
	logf("critical", format, args...)
}

func sleepOneSecond() {
	time.Sleep(time.Second)
}

type stdLogBridge struct{}

func (stdLogBridge) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		logf("info", "%s", msg)
	}
	return len(p), nil
}

func initThirdPartyLogger() {
	stdLogOnce.Do(func() {
		log.SetFlags(0)
		log.SetPrefix("")
		log.SetOutput(stdLogBridge{})
	})
}
