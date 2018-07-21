package main

import (
	"log"
	"net"

	"github.com/daoluan/gosocks/common"
)

type ClientProxy struct {
	src_conn net.Conn
	dst_conn net.Conn
	reqbuf   []byte
	reqlen   int
	state    int8
}

func (c *ClientProxy) Init(src_conn net.Conn) {
	c.src_conn = src_conn
	c.dst_conn = nil
	c.reqlen = 0
	c.state = -1
	c.reqbuf = make([]byte, 100000)
}

func (c *ClientProxy) Feed() bool {
	if c.src_conn == nil {
		log.Println("srconn nil")
		return false
	}

	log.Println("reading from localproxy c.reqlen", c.reqlen, len(c.reqbuf))
	reqlen, err := c.src_conn.Read(c.reqbuf[c.reqlen:])
	log.Println("read from localproxy reqlen", reqlen, len(c.reqbuf))
	if err != nil {
		log.Println("haha error", err.Error())
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
	log.Println(domain)
	tcp_addr, err := net.ResolveTCPAddr("tcp4", domain)
	if err != nil {
		log.Println(domain, "ResolveTCPAddr error: ", err.Error(), c.reqlen)
		return false
	}

	c.dst_conn, err = net.DialTCP("tcp4", nil, tcp_addr)
	if err != nil {
		log.Println(domain, "DialTcp error: ", err.Error(), c.reqlen)
		c.dst_conn = nil
		return false
	}
	// inorder to notify succeed connect dst server
	c.src_conn.Write([]byte{9})

	// handle proxy to client
	log.Println("proxy request")
	c.state = 1
	c.reqlen = 0
	return true
}

func (c *ClientProxy) HandleProxy() bool {
	for {
		cmd, content, left, err := common.UnpackPacket(c.reqbuf[:c.reqlen])

		if err != nil || cmd != 2 {
			if err != nil {
				log.Println("unpack packet error: ringbuf_len = ", c.reqlen,
					", content len = [", c.reqbuf[1:5], "]",
					", cmd = ", c.reqbuf[0:2],
					", reqlen = ", c.reqlen)
			} else if cmd != 2 {
				log.Println("error pkg, cmd: ", cmd, "error: ", err)
			}

			if err != nil && cmd == 0 {
				return true
			}
			return false
		}

		c.reqbuf = make([]byte, 100000)
		copy(c.reqbuf[0:], left)
		c.reqlen = len(left)

		// handle the complete package
		plaintext, _ := common.DecryptDES(content)
		c.dst_conn.Write(plaintext)
		log.Println("<<< write plaintext to webserver len(plaintext)=", len(plaintext), "reqlen=", c.reqlen,
			len(c.reqbuf))

		if c.reqlen == 0 {
			break
		}
		// if cmd == 2 && c.reqlen > 0 {
		// 	continue
		// }
		// break
	}
	return true
}

func (c *ClientProxy) GetState() int8 {
	return c.state
}

func (c *ClientProxy) Fini() {
	log.Println("fini")
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
		buf := make([]byte, 151200)
		log.Println("reading from webserver")
		reqlen, err := dst_conn.Read(buf[0:])
		log.Println("read from webserver read return", "reqlen=", reqlen)
		if err != nil {
			log.Println("read from webserver error: ", err.Error())
			break
		}
		if reqlen == 0 {
			break
		}

		log.Println("yindan ", buf[0:10])
		ciphertext, _ := common.EncrptDES(buf[:reqlen])
		sendbuf := common.PackPacket(2, ciphertext)
		log.Println(">>> recv len = ", reqlen,
			", send to client: ", len(sendbuf),
			", encrpt content len = ", len(ciphertext))
		src_conn.Write(sendbuf)
	}
}
