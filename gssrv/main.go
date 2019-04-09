package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/daoluan/gosocks/common"
)

type Config struct {
	ListenHost string `json: "ListenHost"`
	ListenPort int    `json: "ListenPort"`
	ConnType   string `json: "ConnType"`
}

func LoadConfig() (config Config) {
	file, _ := ioutil.ReadFile("gssrv.json")
	data := Config{}
	_ = json.Unmarshal([]byte(file), &data)
	return data
}

var config Config

func main() {
	common.InitLog()
	config = LoadConfig()
	fmt.Println(config)

	l, err := net.Listen(config.ConnType, config.ListenHost+":"+strconv.Itoa(config.ListenPort))
	if err != nil {
		log.Println("error listening:", err.Error())
		os.Exit(1)
	}
	defer l.Close()

	log.Println("listening on " + config.ListenHost + ":" + strconv.Itoa(config.ListenPort))

	for {
		// listen for an incoming connection
		conn, err := l.Accept()
		if err != nil {
			log.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}

		go handleNewRequest(conn)
	}
}

func handleNewRequest(src_conn net.Conn) {
	var cp ClientProxy
	cp.Init(src_conn)
	defer cp.Fini()

	for {
		if cp.GetState() == common.STATE_NONE {
			if !cp.HandleAuth() {
				log.Println("auth error")

				break
			}
			go common.ProxyPrivPacket(cp.src_conn, cp.dst_conn)
		} else if cp.GetState() == common.STATE_PROXY {
			if !common.ProxyRsPacket(cp.dst_conn, cp.src_conn) {
				log.Println("ProxyRsPacket error")
				break
			}
		}
	}
}
