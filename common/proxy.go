package common

import (
	"log"
	"net"
)

func ProxyRsPacket(src_conn net.Conn, dst_conn net.Conn) bool {
	// 100k at most
	reqbuf := make([]byte, 100000)
	reqlen, err := src_conn.Read(reqbuf[0:])
	if err != nil {
		log.Printf("error in Read: %s", err.Error())
		return false
	}
	ciphertext, _ := EncrptDES(reqbuf[:reqlen])

	log.Printf("<<< write to remote proxy = %d", len(ciphertext))
	SendPrivPacket(dst_conn, 2, ciphertext)
	return true
}

func ProxyPrivPacket(src_conn net.Conn, dst_conn net.Conn) {
	defer src_conn.Close()
	defer dst_conn.Close()

	for {
		cmd, content, err := RecvPrivPacket(src_conn)
		if err != nil {
			log.Printf("error in RecvPrivPacket: %s", err.Error())
			return
		} else if cmd != 2 {
			log.Printf("unknown cmd=%s", cmd)
			return
		}

		plaintext, _ := DecryptDES(content)
		log.Println(">>> write to browser", len(plaintext), len(content))
		dst_conn.Write(plaintext)
	}
}
