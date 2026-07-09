package common

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	CANDY_VERSION = "6.1.8-go"
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
	noTimestampOutput atomic.Bool
	minLogPriority    atomic.Int32
	logMutex          sync.Mutex
	logOutput         io.Writer = os.Stdout
	logCloser         io.Closer
	stdLogOnce        sync.Once
)

const (
	logPriorityDebug int32 = iota
	logPriorityInfo
	logPriorityWarn
	logPriorityError
	logPriorityCritical
)

func init() {
	minLogPriority.Store(logPriorityInfo)
}

func setDebug(enabled bool) {
	if enabled {
		minLogPriority.Store(logPriorityDebug)
		return
	}
	minLogPriority.Store(logPriorityInfo)
}

func setNoTimestamp(enabled bool) {
	noTimestampOutput.Store(enabled)
}

func setLogLevel(level string) error {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "information", "info":
		minLogPriority.Store(logPriorityInfo)
	case "trace", "debug":
		minLogPriority.Store(logPriorityDebug)
	case "warning", "warn":
		minLogPriority.Store(logPriorityWarn)
	case "error":
		minLogPriority.Store(logPriorityError)
	case "fatal", "critical":
		minLogPriority.Store(logPriorityCritical)
	default:
		return fmt.Errorf("unknown log level: %s", level)
	}
	return nil
}

func logPriority(level string) int32 {
	switch strings.ToLower(level) {
	case "debug":
		return logPriorityDebug
	case "warn", "warning":
		return logPriorityWarn
	case "error":
		return logPriorityError
	case "critical", "fatal":
		return logPriorityCritical
	default:
		return logPriorityInfo
	}
}

func logf(level string, format string, args ...any) {
	level = strings.ToLower(level)
	if logPriority(level) < minLogPriority.Load() {
		return
	}

	logMutex.Lock()
	defer logMutex.Unlock()

	out := logOutput
	if out == nil {
		out = os.Stdout
	}
	if noTimestampOutput.Load() {
		_, _ = fmt.Fprintf(out, "[%s] %s\n", level, fmt.Sprintf(format, args...))
		return
	}
	_, _ = fmt.Fprintf(out, "[%s] [%s] %s\n", getCurrentTimeWithMillis(), level, fmt.Sprintf(format, args...))
}

func debugf(format string, args ...any) {
	logf("debug", format, args...)
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
