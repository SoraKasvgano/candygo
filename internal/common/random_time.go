package common

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"time"
)

func version() string {
	return CANDY_VERSION
}

func create_vmac() string {
	return randomHexString(VMAC_SIZE)
}

func randomUint32() uint32 {
	v, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return uint32(time.Now().UnixNano())
	}
	return uint32(v.Uint64())
}

func randomHexString(length int) string {
	if length <= 0 {
		return ""
	}
	bytesLen := (length + 1) / 2
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	out := hex.EncodeToString(buf)
	if len(out) > length {
		return out[:length]
	}
	return out
}

func unixTime() int64 {
	return time.Now().Unix()
}

func bootTime() int64 {
	return time.Now().UnixMilli()
}

func getCurrentTimeWithMillis() string {
	return time.Now().Format("2006-01-02 15:04:05.000")
}
