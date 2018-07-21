package main

import (
	"errors"
	"log"
	"net"

	"github.com/daoluan/gosocks/common"
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
	s.reqlen = 0
	s.reqbuf = make([]byte, 100000)
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

	log.Println("reading from remote proxy c.reqlen=", c.reqlen, len(c.reqbuf))
	reqlen, err := c.dst_conn.Read(c.reqbuf[c.reqlen:])
	log.Println("read from remote proxy reqlen=", reqlen, len(c.reqbuf))
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
			log.Println("unpack packet error: reqlen = ", s.reqlen,
				", content len = [", s.reqbuf[1:5], "]",
				", cmd = ", s.reqbuf[0:2],
				", reqlen = ", s.reqlen,
				err.Error())
		} else if cmd != 2 {
			log.Println("error pkg, cmd: ", cmd, "error: ", err)
		}

		if cmd == 0 && err != nil {
			return 0, nil, errors.New("not enough")
		}

		return -1, nil, errors.New("invalid packet")
	}

	// fix buf
	log.Println("*** cmd=", cmd, "len(left)=", len(left))
	s.reqbuf = make([]byte, 100000)
	copy(s.reqbuf[0:], left)
	s.reqlen = len(left)

	return cmd, content, nil
}
