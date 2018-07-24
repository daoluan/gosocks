package main

import (
	"log"
	"net"
	"os"

	"github.com/daoluan/gosocks/common"
)

const (
	CONN_HOST = "127.0.0.1"
	CONN_PORT = "5556"
	CONN_TYPE = "tcp4"
	PROXY_SERVER_HOST = "127.0.0.1"
	PROXY_SERVER_PORT = "8080"
)

func main() {
	common.InitLog()

	l, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
	if err != nil {
		log.Println("error listening:", err.Error())
		os.Exit(1)
	}
	defer l.Close()

	log.Println("listening on " + CONN_HOST + ":" + CONN_PORT)

	for {
		// listen for an incoming connection
		conn, err := l.Accept()
		if err != nil {
			log.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}

		go HandleNewRequest(conn)
	}
}

func HandleNewRequest(src_conn net.Conn) {
	var cp ClientProxy
	cp.Init()
	cp.src_conn = src_conn

	defer cp.Fini()

	for {
		if cp.GetState() == common.STATE_NONE {
			if !cp.HandleAuth() {
				log.Println("auth erorr")
				break
			}
		} else if cp.GetState() == common.STATE_AUTH {
			if !cp.HandleConnect() {
				log.Println("connect erorr")
				break
			}

			go common.ProxyPrivPacket(cp.dst_conn, cp.src_conn)
		} else if cp.GetState() == common.STATE_PROXY {
			if !common.ProxyRsPacket(cp.src_conn, cp.dst_conn) {
				log.Printf("ProxyRsPacket error")
				break
			}
		}
	}
}
