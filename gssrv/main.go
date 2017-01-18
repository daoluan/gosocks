package main

import (
	"fmt"
	"net"
	"os"
)

const (
	// CONN_HOST = "0.0.0.0"
	CONN_HOST = "127.0.0.1"
	CONN_PORT = "5557"
	CONN_TYPE = "tcp"
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

		go handleRequest(conn)
	}
}

func handleRequest(src_conn net.Conn) {
	var cp ClientProxy
	cp.Init(src_conn)
	defer cp.Fini()

	for {
		if !cp.Feed() {
			break
		}

		if cp.GetState() < 0 {
			if !cp.HandleAuth() {
				break
			}
		} else if cp.GetState() > 0 {
			if !cp.HandleProxy() {
				break
			}
		}
	}
}
