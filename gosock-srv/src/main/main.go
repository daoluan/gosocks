package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	buf := make([]byte, 15120)
	ringbuf := make([]byte, 15120)
	var ringbuf_len int = 0
	state := -1
	var dst_conn net.Conn = nil

	for {
		reqlen, err := src_conn.Read(buf)
		if err != nil {
			fmt.Println("error reading: ", err.Error(), reqlen)
			break
		}
		if reqlen == 0 {
			break
		}

		// auth
		if state < 0 {
			if buf[0] == 1 {
				_, content, _, err := unpackPacket(buf[:reqlen])

				encrpt, _ := decryptDES(content)
				domain := string(encrpt)

				tcp_addr, err := net.ResolveTCPAddr("tcp4", domain)
				if err != nil {
					fmt.Println(domain, "ResolveTCPAddr error: ", err.Error(), reqlen)
					return
				}
				dst_conn, err = net.DialTCP("tcp4", nil, tcp_addr)
				if err != nil {
					fmt.Println(domain, "DialTcp error: ", err.Error(), reqlen)
					return
				}
				src_conn.Write([]byte{1})

				// handle proxy to client
				go doProxyRequest(src_conn, dst_conn)
				state = 1
			} else {
				fmt.Println("invalid auth packet")
			}
			continue
		}

		// handle client to proxy
		if state > 0 {
			if ringbuf_len == 0 {
				ringbuf = buf
			} else {
				ringbuf = append(ringbuf[:ringbuf_len], buf[:reqlen]...)
			}
			ringbuf_len = ringbuf_len + reqlen

			for {
				cmd, content, left, err := unpackPacket(ringbuf[:ringbuf_len])
				if err != nil || cmd != 2 {
					if err != nil {
						fmt.Println("unpack packet error: ringbuf_len = ", ringbuf_len,
							", content len = [", ringbuf[1:5], "]",
							", cmd = ", ringbuf[0:2],
							", reqlen = ", reqlen)
					} else if cmd != 2 {
						fmt.Println("error pkg, cmd: ", cmd, "error: ", err)
					}
					break
				}

				ringbuf = left
				ringbuf_len = len(left)

				fmt.Print(
					"client to proxy cmd: ", cmd,
					", content_len: ", len(content),
					", left: ", len(left))

				if len(left) > 0 {
					fmt.Println(", left[0]: ", left[0])
				} else {
					fmt.Println("")
				}

				// handle the complete package
				plaintext, _ := decryptDES(content)
				dst_conn.Write(plaintext)

				if cmd == 2 && ringbuf_len > 0 {
					continue
				}
				break
			}
		}
	}
	defer closeNotNull(src_conn)
	defer closeNotNull(dst_conn)
}

func closeNotNull(conn net.Conn) {
	if conn != nil {
		conn.Close()
	}
}

func encrptDES(text []byte) ([]byte, error) {
	key := []byte("AES256Key-32Characters1234567890")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))
	return ciphertext, nil
}

func decryptDES(text []byte) ([]byte, error) {
	key := []byte("AES256Key-32Characters1234567890")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return text, nil
}

func packPacket(cmd int8, encrpt []byte) []byte {
	out := make([]byte, 1024)
	idx := 0
	out[idx] = byte(cmd)
	idx++
	encrpt_len := uint32(len(encrpt))
	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, encrpt_len)
	out = append(out[:idx], l...)
	idx += 4
	out = append(out[:idx], encrpt...)
	idx += len(encrpt)
	return out[:idx]
}

func unpackPacket(encrpt []byte) (int8, []byte, []byte, error) {
	if len(encrpt) < 5 {
		return 0, nil, nil, errors.New("length error")
	}
	c := int8(encrpt[0])
	real_pkg_len := binary.BigEndian.Uint32(encrpt[1:5])
	left := make([]byte, 1)
	if int(real_pkg_len+5) == len(encrpt) {
		left = nil
	} else if int(real_pkg_len+5) < len(encrpt) {
		left = encrpt[5+real_pkg_len:]
	} else {
		return 0, nil, nil, errors.New("length error")
	}
	return c, encrpt[5 : 5+real_pkg_len], left, nil
}

func doProxyRequest(src_conn net.Conn, dst_conn net.Conn) {
	defer src_conn.Close()
	defer dst_conn.Close()
	for {
		buf := make([]byte, 15120)
		reqlen, err := dst_conn.Read(buf)
		if err != nil {
			fmt.Println("read from webserver error: ", err.Error())
			break
		}
		if reqlen == 0 {
			break
		}

		ciphertext, _ := encrptDES(buf[:reqlen])
		sendbuf := packPacket(2, ciphertext)
		fmt.Println("recv len = ", reqlen,
			", send to client: ", len(sendbuf),
			", encrpt content len = ", len(ciphertext))
		src_conn.Write(sendbuf)
	}
}
