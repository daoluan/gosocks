package main

import (
	"encoding/binary"
	"fmt"
	"github.com/daoluan/gosocks/common"
	"net"
	"strconv"
)

type ClientProxy struct {
	state    int8
	reqbuf   [1000]byte
	reqlen   int
	src_conn net.Conn
	dst_conn net.Conn
}

func (c *ClientProxy) Init() {
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
	c.reqlen, err = c.src_conn.Read(c.reqbuf[c.reqlen:])
	if err != nil {
		return false
	}

	if 0 == c.reqlen {
		return false
	}

	return true
}

func (c *ClientProxy) HandleAuth() bool {
	if c.state > 0 || c.dst_conn == nil {
		return false
	}

	rsp := make([]byte, 2)
	rsp[0] = 0x5
	rsp[1] = 0
	c.src_conn.Write(rsp)
	c.state = 0
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
	port_uint16 := binary.BigEndian.Uint16(c.reqbuf[c.reqlen-2 : c.reqlen])
	port_string := strconv.Itoa(int(port_uint16))
	for i := 0; i < len(port_string); i++ {
		byte_domain[byte_domain_idx] = port_string[i]
		byte_domain_idx++
	}

	ciphertext, _ := common.EncrptDES(byte_domain[:byte_domain_idx])
	conn_req := common.PackPacket(1, ciphertext)
	if conn_req == nil {
		fmt.Println("pack error")
		return false
	}

	var err error = nil
	c.dst_conn, err = net.Dial("tcp", PROXY_SERVER_HOST+":"+PROXY_SERVER_PORT)
	if err != nil {
		fmt.Println("net Dial error: ", err.Error())
		return false
	}

	c.dst_conn.Write(conn_req)
	c.reqlen, err = c.dst_conn.Read(c.reqbuf[0:])
	if err != nil {
		fmt.Println("auth proxy failed: ", err.Error())
		return false
	}

	c.src_conn.Write(conn_rsp)

	// handle proxy to client
	go ProxyResponse(c.dst_conn, c.src_conn)

	c.state = 1

	return true
}

func (c *ClientProxy) HandleProxy() {
	encrypt, _ := common.EncrptDES(c.reqbuf[:c.reqlen])
	sendbuf := common.PackPacket(2, encrypt)

	fmt.Println(
		"reqlen = ", c.reqlen,
		"client to proxy:", len(sendbuf),
		" reqlen: ", c.reqlen)

	c.dst_conn.Write(sendbuf)
}

func (c *ClientProxy) Fini() {
	c.src_conn.Close()
	c.dst_conn.Close()
}

func (c *ClientProxy) GetState() int8 {
	return c.state
}

func (s *ServerProxy) HandleProxy() {
	for {
		if !s.Feed() {
			break
		}

		cmd, content, err := s.Extract()
		if err != nil {
			break
		}

		encrpt, _ := common.DecryptDES(content)
		s.src_conn.Write(encrpt)

		if cmd == 2 && s.reqlen > 0 {
			continue
		}

		break
	}
}
