package main

import (
	"log"
	"net"

	"github.com/daoluan/gosocks/common"
)

type ClientProxy struct {
	src_conn net.Conn
	dst_conn net.Conn
	state    common.ProxyState
}

func (c *ClientProxy) Init(src_conn net.Conn) {
	c.src_conn = src_conn
	c.dst_conn = nil
	c.state = common.STATE_NONE
}

func (c *ClientProxy) HandleAuth() bool {
	cmd, content, err := common.RecvPrivPacket(c.src_conn)
	if err != nil {
		log.Printf("error in RecvPrivPacket: %s", err.Error())
		return false
	} else if cmd != 1 {
		log.Printf("unknown cmd=%s", cmd)
		return false
	}

	log.Printf("recv %d in HandleAuth", len(content))

	encrpt, _ := common.DecryptDES(content)
	domain := string(encrpt)
	log.Printf("connecting domain=%s", domain)

	tcp_addr, err := net.ResolveTCPAddr("tcp4", domain)
	if err != nil {
		log.Printf("domain=%s|error in ResolveTCPAddr: %s", domain, err.Error())
		return false
	}

	c.dst_conn, err = net.DialTCP("tcp4", nil, tcp_addr)
	if err != nil {
		log.Printf("domain=%s|error in DialTCP: %s", domain, err.Error())
		c.dst_conn = nil
		return false
	}

	// inorder to notify succeed connect dst server
	c.src_conn.Write([]byte{9})

	// handle proxy to client
	c.state = common.STATE_PROXY
	return true
}

func (c *ClientProxy) GetState() common.ProxyState {
	return c.state
}

func (c *ClientProxy) Fini() {
	log.Println("ClientProxy fini")
	if c.src_conn != nil {
		c.src_conn.Close()
	}
	if c.dst_conn != nil {
		c.dst_conn.Close()
	}
}

func doProxyRequest(src_conn net.Conn, dst_conn net.Conn) bool {
	defer src_conn.Close()
	defer dst_conn.Close()

	for {
		// 100k at most
		buf := make([]byte, 100000)
		reqlen, err := dst_conn.Read(buf[0:])
		if err != nil || reqlen == 0 {
			log.Printf("read from webserver error: %s", err.Error())
			return false
		}

		ciphertext, _ := common.EncrptDES(buf[:reqlen])

		common.SendPrivPacket(src_conn, 2, ciphertext)
		log.Printf(">>> send %d to local proxy", len(ciphertext))
	}
}
