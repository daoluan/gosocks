package common

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
)

func SendPrivPacket(w io.Writer, cmd int8, content []byte) bool {
	var len uint32 = uint32(len(content))
	log.Printf("SendPrivPacket cmd=%d|len=%d", cmd, len)

	err := binary.Write(w, binary.BigEndian, cmd)
	if err != nil {
		log.Printf("error in Write: %s", err.Error())
		return false
	}
	err = binary.Write(w, binary.BigEndian, &len)
	if err != nil {
		log.Printf("error in Write: %s", err.Error())
		return false
	}
	w.Write(content)
	return true
}

func RecvPrivPacket(r io.Reader) (int8, []byte, error) {
	var cmd int8 = 0
	var l uint32 = 0
	err := binary.Read(r, binary.BigEndian, &cmd)
	if err != nil {
		log.Printf("error in Read: %s", err.Error())
		return 0, nil, errors.New("error in Read")
	}
	err = binary.Read(r, binary.BigEndian, &l)
	if err != nil {
		log.Printf("error in Read: %s", err.Error())
		return 0, nil, errors.New("error in Read")
	}

	log.Printf("RecvPrivPacket cmd=%d|len=%d", cmd, l)

	content := make([]byte, l)
	io.ReadFull(r, content)
	return cmd, content, nil
}
