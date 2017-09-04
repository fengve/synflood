package main

import (
	"encoding/binary"
	"syscall"
)

const (
	tcpHeaderLen    = 20
	tcpMaxHeaderLen = 60
)

// A tcp header
type tcpHeader struct {
	Src     int    //源端口
	Dst     int    //目的端口
	Seq     int    //序号
	Ack     int    //确认号
	Len     int    //头部长度
	Rsvd    int    //保留位
	Flag    int    //标志位
	Win     int    //窗口大小
	Sum     int    //校验和
	Urp     int    //紧急指针
	Options []byte // 选项, extension headers
}

// Marshal encode tcp header
func (h *tcpHeader) Marshal() ([]byte, error) {
	if h == nil {
		return nil, syscall.EINVAL
	}

	hdrlen := tcpHeaderLen + len(h.Options)
	b := make([]byte, hdrlen)

	//版本和头部长度
	binary.BigEndian.PutUint16(b[0:2], uint16(h.Src))
	binary.BigEndian.PutUint16(b[2:4], uint16(h.Dst))

	binary.BigEndian.PutUint32(b[4:8], uint32(h.Seq))
	binary.BigEndian.PutUint32(b[8:12], uint32(h.Ack))

	b[12] = uint8(hdrlen/4<<4 | 0)
	//TODO  Rsvd

	b[13] = uint8(h.Flag)

	binary.BigEndian.PutUint16(b[14:16], uint16(h.Win))
	binary.BigEndian.PutUint16(b[16:18], uint16(h.Sum))
	binary.BigEndian.PutUint16(b[18:20], uint16(h.Urp))

	if len(h.Options) > 0 {
		copy(b[tcpHeaderLen:], h.Options)
	}

	return b, nil
}
