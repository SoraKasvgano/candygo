package app

import (
	"sync/atomic"
)

type Server struct {
	ws      WebSocketServer
	running atomic.Bool
}

func (s *Server) setWebSocket(uri string) {
	_ = s.ws.SetWebSocket(uri)
}

func (s *Server) setPassword(password string) {
	_ = s.ws.SetPassword(password)
}

func (s *Server) setDHCP(cidr string) {
	_ = s.ws.SetDHCP(cidr)
}

func (s *Server) setSdwan(sdwan string) {
	_ = s.ws.SetSdwan(sdwan)
}

func (s *Server) run() {
	s.running.Store(true)
	_ = s.ws.Run()
	for s.running.Load() {
		sleepOneSecond()
	}
	_ = s.ws.Shutdown()
}

func (s *Server) shutdown() {
	s.running.Store(false)
}
