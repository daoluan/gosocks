package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"

	"github.com/daoluan/gosocks/common"
)

type ClientProxy struct {
	state    common.ProxyState
	src_conn net.Conn
	dst_conn net.Conn
}

func (c *ClientProxy) Init() {
	log.Println("client proxy init")
	c.state = common.STATE_NONE
	c.src_conn = nil
	c.dst_conn = nil
}
func (c *ClientProxy) HandleAuth() bool {
	if c.state > common.STATE_NONE {
		log.Println("unknown state in auth")
		return false
	}

	buf := make([]byte, 3)
	n, err := io.ReadFull(c.src_conn, buf)
	if err != nil {
		log.Printf("error in ReadFull: %s", err.Error())
		return false
	}

	log.Printf("HandleAuth recvlen=%d %s", n, buf)

	// no pwd
	rsp := []byte{0, 0}
	rsp[0] = 0x5
	rsp[1] = 0
	c.src_conn.Write(rsp)
	c.state = common.STATE_AUTH
	return true
}

func (c *ClientProxy) HandleConnect() bool {
	reqbuf := make([]byte, 256)
	reqlen, err := c.src_conn.Read(reqbuf)
	if err != nil {
		log.Printf("error in Read: %s", err.Error())
		return false
	}
	log.Printf("HandleConnect recvlen=%d", reqlen)
	conn_rsp := make([]byte, reqlen)

	conn_rsp[0] = 0x5
	conn_rsp[1] = 0 // succeeded
	conn_rsp[2] = 0
	conn_rsp[3] = reqbuf[3]
	for i := 4; i < reqlen; i++ {
		conn_rsp[i] = reqbuf[i]
	}

	byte_domain_idx := 0
	byte_domain := make([]byte, 256)
	for i := 5; i < reqlen-2; i++ {
		byte_domain[byte_domain_idx] = reqbuf[i]
		byte_domain_idx++
	}
	byte_domain[byte_domain_idx] = ':'
	byte_domain_idx++

	port_uint16 := binary.BigEndian.Uint16(reqbuf[reqlen-2 : reqlen])
	port_string := strconv.Itoa(int(port_uint16))
	for i := 0; i < len(port_string); i++ {
		byte_domain[byte_domain_idx] = port_string[i]
		byte_domain_idx++
	}
	log.Printf("domain=%s", string(byte_domain[:byte_domain_idx]))

	ciphertext, _ := common.EncrptDES(byte_domain[:byte_domain_idx])

	c.dst_conn, err = net.Dial("tcp4", PROXY_SERVER_HOST+":"+PROXY_SERVER_PORT)
	if err != nil {
		log.Printf("net Dial error: %s", err.Error())
		return false
	}

	bres := common.SendPrivPacket(c.dst_conn, 1, ciphertext)
	if !bres {
		log.Printf("error in SendPrivPacket: %s", err.Error())
		return false
	}

	reqlen, err = c.dst_conn.Read(reqbuf[0:1]) // skip it
	if err != nil {
		log.Printf("auth proxy failed: %s", err.Error())
		return false
	}

	c.src_conn.Write(conn_rsp)

	c.state = common.STATE_PROXY
	return true
}

func (c *ClientProxy) HandleProxy() bool {
	// 100k at most
	reqbuf := make([]byte, 100000)
	reqlen, err := c.src_conn.Read(reqbuf[0:])
	if err != nil {
		log.Printf("error in Read: %s", err.Error())
		return false
	}
	ciphertext, _ := common.EncrptDES(reqbuf[:reqlen])

	log.Printf("<<< write to remote proxy = %d", len(ciphertext))
	log.Println("yindan", ciphertext[0:10])
	common.SendPrivPacket(c.dst_conn, 2, ciphertext)
	return true
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

func (c *ClientProxy) GetState() common.ProxyState {
	return c.state
}

func (s *ServerProxy) HandleProxy() bool {
	for {
		cmd, content, err := common.RecvPrivPacket(s.dst_conn)
		if err != nil || cmd != 2 {
			log.Printf("error in RecvPrivPacket: %s|cmd=%d", err.Error(), cmd)
			return false
		}

		plaintext, _ := common.DecryptDES(content)
		log.Println(">>> write to browser", len(plaintext), "reqlen=", s.reqlen, "content.len=",
			len(content))
		// log.Println("yindan ", plaintext[0:10])
		s.src_conn.Write(plaintext)
	}

	return true
}
