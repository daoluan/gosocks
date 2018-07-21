package main

import (
	"net"
)

type ServerProxy struct {
	src_conn net.Conn
	dst_conn net.Conn
	reqbuf   []byte
	reqlen   int
}

func (s *ServerProxy) Init(src_conn net.Conn, dst_conn net.Conn) bool {
	if src_conn == nil || dst_conn == nil {
		return false
	}

	s.src_conn = src_conn
	s.dst_conn = dst_conn
	return true
}

func (s *ServerProxy) Fini() {
	if s.src_conn != nil {
		s.src_conn.Close()
	}
	if s.dst_conn != nil {
		s.dst_conn.Close()
	}
}
