package main

import (
	"encoding/binary"
	"log"
	"net"
	"strconv"

	"github.com/daoluan/gosocks/common"
)

type ClientProxy struct {
	state    int8
	reqbuf   [100000]byte
	reqlen   int
	src_conn net.Conn
	dst_conn net.Conn
}

func (c *ClientProxy) Init() {
	log.Println("init")
	c.state = -1
	c.reqlen = 0
	c.src_conn = nil
	c.dst_conn = nil
}

func (c *ClientProxy) Feed() bool {
	if c.src_conn == nil {
		return false
	}

	var err error = nil
	log.Println("reading from browser c.reqlen=", c.reqlen, len(c.reqbuf))
	c.reqlen, err = c.src_conn.Read(c.reqbuf[c.reqlen:])
	log.Println("read from browser reqlen=", c.reqlen)
	if err != nil {
		log.Println("haha error: ", err.Error())
		return false
	}

	if 0 == c.reqlen {
		return false
	}

	return true
}

func (c *ClientProxy) HandleAuth() bool {
	if c.state > 0 {
		return false
	}

	rsp := make([]byte, 2)
	rsp[0] = 0x5
	rsp[1] = 0
	c.src_conn.Write(rsp)
	c.state = 0
	c.reqlen = 0
	return true
}

func (c *ClientProxy) HandleConnect() bool {
	conn_rsp := make([]byte, c.reqlen)
	conn_rsp[0] = 0x5
	conn_rsp[1] = 0 // succeeded
	conn_rsp[2] = 0
	conn_rsp[3] = c.reqbuf[3]
	for i := 4; i < c.reqlen; i++ {
		conn_rsp[i] = c.reqbuf[i]
	}

	byte_domain_idx := 0
	byte_domain := make([]byte, 15000)
	for i := 5; i < c.reqlen-2; i++ {
		byte_domain[byte_domain_idx] = c.reqbuf[i]
		byte_domain_idx++
	}
	byte_domain[byte_domain_idx] = ':'
	byte_domain_idx++
	log.Println("handle domain only", string(byte_domain[:byte_domain_idx]))

	port_uint16 := binary.BigEndian.Uint16(c.reqbuf[c.reqlen-2 : c.reqlen])
	port_string := strconv.Itoa(int(port_uint16))
	for i := 0; i < len(port_string); i++ {
		byte_domain[byte_domain_idx] = port_string[i]
		byte_domain_idx++
	}
	log.Println("handle domain", string(byte_domain[:byte_domain_idx]))

	ciphertext, _ := common.EncrptDES(byte_domain[:byte_domain_idx])
	conn_req := common.PackPacket(1, ciphertext)
	if conn_req == nil {
		log.Println("pack error")
		return false
	}

	var err error = nil
	log.Println("connecting")
	c.dst_conn, err = net.Dial("tcp4", PROXY_SERVER_HOST+":"+PROXY_SERVER_PORT)
	log.Println("connected")
	if err != nil {
		log.Println("net Dial error: ", err.Error())
		return false
	}

	c.dst_conn.Write(conn_req)
	c.reqlen, err = c.dst_conn.Read(c.reqbuf[0:1]) // skip it
	if err != nil {
		log.Println("auth proxy failed: ", err.Error())
		return false
	}
	c.reqlen = 0
	c.src_conn.Write(conn_rsp)

	c.state = 1

	return true
}

func (c *ClientProxy) HandleProxy() {
	encrypt, _ := common.EncrptDES(c.reqbuf[:c.reqlen])
	sendbuf := common.PackPacket(2, encrypt)

	log.Println(
		"<<< write to remote proxy reqlen = ", c.reqlen,
		"client to proxy:", len(sendbuf),
		" reqlen: ", c.reqlen)

	c.reqlen = 0
	c.dst_conn.Write(sendbuf)
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

func (c *ClientProxy) GetState() int8 {
	return c.state
}

func (s *ServerProxy) HandleProxy() bool {
	for {

		if !s.Feed() {
			return false
		}

		for {
			// log.Println((s.reqbuf[:s.reqlen]))
			cmd, content, err := s.Extract()
			if cmd == 0 {
				log.Println("not enougn")
				break
			}

			if err != nil {
				return false
			}

			encrpt, _ := common.DecryptDES(content)
			// log.Println("deccontent=",encrpt,len(encrpt))
			log.Println(">>> write to browser", len(encrpt), "reqlen=", s.reqlen, "content.len=",
				len(content))
			log.Println("yindan ", encrpt[0:10])
			s.src_conn.Write(encrpt)

			if s.reqlen == 0 {
				break
			}

			// if cmd == 2 && s.reqlen > 0 {
			// 	continue
			// }
		}
	}
}
