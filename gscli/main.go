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
	// PROXY_SERVER_HOST = "127.0.0.1"
	PROXY_SERVER_HOST = "47.75.123.130"
	PROXY_SERVER_PORT = "8080"
)

func main() {
	common.InitLog()

	log.Printf("hello")
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
	log.Println("new request")
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

			go ProxyResponse(cp.src_conn, cp.dst_conn)
		} else if cp.GetState() == common.STATE_PROXY {
			if !cp.HandleProxy() {
				log.Printf("error in HandleProxy")
				break
			}
		}
	}
	log.Println("over")
}

func ProxyResponse(src_conn net.Conn, dst_conn net.Conn) {
	var sp ServerProxy
	if !sp.Init(src_conn, dst_conn) {
		return
	}
	defer sp.Fini()

	if !sp.HandleProxy() {
		log.Println("ProxyResponse error")
	}
}
