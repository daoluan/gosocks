package main

import (
	"fmt"
	"github.com/daoluan/gosocks/common"
	"net"
)

type ClientProxy struct {
	src_conn net.Conn
	dst_conn net.Conn
	reqbuf   []byte
	reqlen   int
	state    int8
}

func (c *ClientProxy) Init(src_conn net.Conn) {
	c.src_conn = nil
	c.dst_conn = nil
	c.reqlen = 0
	c.state = -1
}

func (c *ClientProxy) Feed() bool {
	if c.src_conn == nil {
		return false
	}

	reqlen, err := c.src_conn.Read(c.reqbuf[c.reqlen:])
	if err != nil {
		return false
	}

	// fix c.reqlen
	c.reqlen = c.reqlen + reqlen
	return true
}

func (c *ClientProxy) HandleAuth() bool {
	_, content, _, err := common.UnpackPacket(c.reqbuf[:c.reqlen])
	encrpt, _ := common.DecryptDES(content)
	domain := string(encrpt)
	tcp_addr, err := net.ResolveTCPAddr("tcp4", domain)
	if err != nil {
		fmt.Println(domain, "ResolveTCPAddr error: ", err.Error(), c.reqlen)
		return false
	}

	c.dst_conn, err = net.DialTCP("tcp4", nil, tcp_addr)
	if err != nil {
		fmt.Println(domain, "DialTcp error: ", err.Error(), c.reqlen)
		return false
	}
	c.src_conn.Write([]byte{1})
	// handle proxy to client
	go doProxyRequest(c.src_conn, c.dst_conn)
	c.state = 1
	return true
}

func (c *ClientProxy) HandleProxy() bool {
	for {
		cmd, content, left, err := common.UnpackPacket(c.reqbuf[:c.reqlen])
		if err != nil || cmd != 2 {
			if err != nil {
				fmt.Println("unpack packet error: ringbuf_len = ", c.reqlen,
					", content len = [", c.reqbuf[1:5], "]",
					", cmd = ", c.reqbuf[0:2],
					", reqlen = ", c.reqlen)
			} else if cmd != 2 {
				fmt.Println("error pkg, cmd: ", cmd, "error: ", err)
			}
			return false
		}

		c.reqbuf = left
		c.reqlen = len(left)

		// handle the complete package
		plaintext, _ := common.DecryptDES(content)
		c.dst_conn.Write(plaintext)

		if cmd == 2 && c.reqlen > 0 {
			continue
		}
		break
	}
	return true
}

func (c *ClientProxy) GetState() int8 {
	return c.state
}

func (c *ClientProxy) Fini() {
	if c.src_conn != nil {
		c.src_conn.Close()
	}
	if c.dst_conn != nil {
		c.dst_conn.Close()
	}
}

func doProxyRequest(src_conn net.Conn, dst_conn net.Conn) {
	defer src_conn.Close()
	defer dst_conn.Close()

	for {
		buf := make([]byte, 15120)
		reqlen, err := dst_conn.Read(buf)
		if err != nil {
			fmt.Println("read from webserver error: ", err.Error())
			break
		}
		if reqlen == 0 {
			break
		}

		ciphertext, _ := common.EncrptDES(buf[:reqlen])
		sendbuf := common.PackPacket(2, ciphertext)
		fmt.Println("recv len = ", reqlen,
			", send to client: ", len(sendbuf),
			", encrpt content len = ", len(ciphertext))
		src_conn.Write(sendbuf)
	}
}
