package common

import "time"

type Thread struct {
	done chan struct{}
}

func NewThread(fn func()) *Thread {
	t := &Thread{done: make(chan struct{})}
	go func() {
		defer close(t.done)
		fn()
	}()
	return t
}

func (t *Thread) Join() {
	if t == nil {
		return
	}
	<-t.done
}

func CandySystem() string {
	return candySystem()
}

func SetDebug(enabled bool) {
	setDebug(enabled)
}

func SetNoTimestamp(enabled bool) {
	setNoTimestamp(enabled)
}

func Debugf(format string, args ...any) {
	debugf(format, args...)
}

func Infof(format string, args ...any) {
	infof(format, args...)
}

func Warnf(format string, args ...any) {
	warnf(format, args...)
}

func Errorf(format string, args ...any) {
	errorf(format, args...)
}

func Criticalf(format string, args ...any) {
	criticalf(format, args...)
}

func SleepOneSecond() {
	sleepOneSecond()
}

func InitThirdPartyLogger() {
	initThirdPartyLogger()
}

func Version() string {
	return version()
}

func CreateVMAC() string {
	return create_vmac()
}

func RandomUint32() uint32 {
	return randomUint32()
}

func RandomHexString(length int) string {
	return randomHexString(length)
}

func UnixTime() int64 {
	return unixTime()
}

func BootTime() int64 {
	return bootTime()
}

func GetCurrentTimeWithMillis() string {
	return getCurrentTimeWithMillis()
}

func NewIP4(ip string) IP4 {
	return newIP4(ip)
}

func (ip *IP4) FromString(v string) int {
	return ip.fromString(v)
}

func (ip *IP4) FromBytes(b []byte) int {
	return ip.fromBytes(b)
}

func (ip IP4) Bytes() []byte {
	return ip.bytes()
}

func (ip IP4) ToString() string {
	return ip.toString()
}

func (ip IP4) ToUint32() uint32 {
	return ip.toUint32()
}

func (ip *IP4) FromUint32(v uint32) {
	ip.fromUint32(v)
}

func (ip IP4) And(another IP4) IP4 {
	return ip.and(another)
}

func (ip IP4) Or(another IP4) IP4 {
	return ip.or(another)
}

func (ip IP4) Xor(another IP4) IP4 {
	return ip.xor(another)
}

func (ip IP4) Not() IP4 {
	return ip.not()
}

func (ip IP4) NextIP() IP4 {
	return ip.next()
}

func (ip IP4) ToPrefix() int {
	return ip.toPrefix()
}

func (ip *IP4) FromPrefix(prefix int) int {
	return ip.fromPrefix(prefix)
}

func (ip IP4) Empty() bool {
	return ip.empty()
}

func (ip *IP4) Reset() {
	ip.reset()
}

func (a *Address) IsValid() bool {
	return a.isValid()
}

func (a *Address) FromCidr(cidr string) int {
	return a.fromCidr(cidr)
}

func (a Address) ToCidr() string {
	return a.toCidr()
}

func (a Address) Empty() bool {
	return a.empty()
}

func (rt SysRouteEntry) Encode() []byte {
	return rt.encode()
}

func DecodeSysRouteEntry(data []byte) (SysRouteEntry, bool) {
	return decodeSysRouteEntry(data)
}

const Ip4HeaderSize = ip4HeaderSize

func Ip4HeaderIsIPv4(buffer []byte) bool {
	return ip4HeaderIsIPv4(buffer)
}

func Ip4HeaderIsIPIP(buffer []byte) bool {
	return ip4HeaderIsIPIP(buffer)
}

func Ip4HeaderSAddr(buffer []byte) IP4 {
	return ip4HeaderSAddr(buffer)
}

func Ip4HeaderDAddr(buffer []byte) IP4 {
	return ip4HeaderDAddr(buffer)
}

func Ip4HeaderSetSAddr(buffer []byte, ip IP4) {
	ip4HeaderSetSAddr(buffer, ip)
}

func Ip4HeaderSetDAddr(buffer []byte, ip IP4) {
	ip4HeaderSetDAddr(buffer, ip)
}

func Ip4HeaderSetProtocol(buffer []byte, protocol byte) {
	ip4HeaderSetProtocol(buffer, protocol)
}

func PackIPIP(payload []byte, src, dst IP4) []byte {
	return packIPIP(payload, src, dst)
}

func ClampInt32(v int64) int32 {
	return clampInt32(v)
}

func AppendCompatIPKeyBytes(dst []byte, ip IP4) []byte {
	return appendCompatIPKeyBytes(dst, ip)
}

func NativeLittleEndian() bool {
	return nativeLittleEndian()
}

func IsIgnorableUDPReadError(err error) bool {
	return isIgnorableUDPReadError(err)
}

func TimeAfterOneSecond() <-chan time.Time {
	return time.After(time.Second)
}
