package main

import (
	"errors"
	"fmt"
	"github.com/daoluan/gosocks/common"
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

func (c *ServerProxy) Feed() bool {
	if c.dst_conn == nil {
		return false
	}

	reqlen, err := c.dst_conn.Read(c.reqbuf[c.reqlen:])
	if err != nil {
		return false
	}

	c.reqlen += reqlen

	if 0 == c.reqlen {
		return false
	}

	return true
}

func (s *ServerProxy) Extract() (int8, []byte, error) {
	cmd, content, left, err := common.UnpackPacket(s.reqbuf[:s.reqlen])
	if err != nil || cmd != 2 {
		if err != nil {
			fmt.Println("unpack packet error: reqlen = ", s.reqlen,
				", content len = [", s.reqbuf[1:5], "]",
				", cmd = ", s.reqbuf[0:2],
				", reqlen = ", s.reqlen)
		} else if cmd != 2 {
			fmt.Println("error pkg, cmd: ", cmd, "error: ", err)
		}
		return 0, nil, errors.New("invalid packet")
	}

	// fix buf
	s.reqbuf = left
	s.reqlen = len(left)

	return cmd, content, nil
}
