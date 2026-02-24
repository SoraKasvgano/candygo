package main

import (
	"sync/atomic"
)

type Server struct {
	ws      WebSocketServer
	running atomic.Bool
}

func (s *Server) setWebSocket(uri string) {
	_ = s.ws.setWebSocket(uri)
}

func (s *Server) setPassword(password string) {
	_ = s.ws.setPassword(password)
}

func (s *Server) setDHCP(cidr string) {
	_ = s.ws.setDHCP(cidr)
}

func (s *Server) setSdwan(sdwan string) {
	_ = s.ws.setSdwan(sdwan)
}

func (s *Server) run() {
	s.running.Store(true)
	_ = s.ws.run()
	for s.running.Load() {
		sleepOneSecond()
	}
	_ = s.ws.shutdown()
}

func (s *Server) shutdown() {
	s.running.Store(false)
}
