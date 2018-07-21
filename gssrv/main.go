package main

import (
	"log"
	"net"
	"os"

	"github.com/daoluan/gosocks/common"
)

const (
	CONN_HOST = "0.0.0.0"
	// CONN_HOST = "127.0.0.1"
	CONN_PORT = "8080"
	CONN_TYPE = "tcp4"
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

		go handleRequest(conn)
	}
}

func handleRequest(src_conn net.Conn) {
	log.Println("new request")
	var cp ClientProxy
	cp.Init(src_conn)
	defer cp.Fini()

	for {
		log.Println("state", cp.state)

		if cp.GetState() == common.STATE_NONE {
			if !cp.HandleAuth() {
				log.Println("auth error")

				break
			}
			go doProxyRequest(cp.src_conn, cp.dst_conn)
		} else if cp.GetState() == common.STATE_PROXY {
			if !cp.HandleProxy() {
				log.Println("HandleProxy error")
				break
			}
		}
	}
}
