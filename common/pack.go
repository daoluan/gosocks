package common

import (
	"encoding/binary"
	"errors"
)

func PackPacket(cmd int8, encrpt []byte) []byte {
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

func UnpackPacket(encrpt []byte) (int8, []byte, []byte, error) {
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
