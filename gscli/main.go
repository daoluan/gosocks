package main

import (
	"fmt"
	"net"
	"os"
)

const (
	CONN_HOST         = "127.0.0.1"
	CONN_PORT         = "5556"
	CONN_TYPE         = "tcp"
	PROXY_SERVER_HOST = "127.0.0.1"
	// PROXY_SERVER_HOST = "52.68.46.171"
	PROXY_SERVER_PORT = "5557"
)

func main() {
	l, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
	if err != nil {
		fmt.Println("error listening:", err.Error())
		os.Exit(1)
	}
	defer l.Close()

	fmt.Println("listening on " + CONN_HOST + ":" + CONN_PORT)

	for {
		// listen for an incoming connection
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}

		go HandleNewRequest(conn)
	}
}

func HandleNewRequest(src_conn net.Conn) {
	var cp ClientProxy
	cp.Init()
	defer cp.Fini()

	for {
		if !cp.Feed() {
			break
		}

		if cp.GetState() < 0 {
			if !cp.HandleAuth() {
				break
			}
		} else if cp.GetState() == 0 {
			if !cp.HandleConnect() {
				break
			}

			go ProxyResponse(cp.src_conn, cp.dst_conn)
		} else if cp.GetState() > 0 {
			cp.HandleProxy()
		}
	}
}

func ProxyResponse(src_conn net.Conn, dst_conn net.Conn) {
	var sp ServerProxy
	if !sp.Init(src_conn, dst_conn) {
		return
	}
	defer sp.Fini()

	sp.HandleProxy()
}
