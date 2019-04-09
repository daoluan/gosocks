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
	ListenHost      string `json: "ListenHost"`
	ListenPort      int    `json: "ListenPort"`
	ConnType        string `json: "ConnType"`
	ProxyServerHost string `json: "ProxyServerHost"`
	ProxyServerPort int    `json: "ProxyServerPort"`
}

func LoadConfig() (config Config) {
	file, _ := ioutil.ReadFile("gscli.json")
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
