package main

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
)

const (
	ipv4Version      = 4
	ipv4HeaderLen    = 20
	ipv4MaxHeaderLen = 60
)

// A ipv4 header
type ipv4Header struct {
	Version  int    // 协议版本 4bit
	Len      int    // 头部长度 4bit
	TOS      int    // 服务类   8bit
	TotalLen int    // 包长		16bit
	ID       int    // id		8bit
	Flags    int    // flags	3bit
	FragOff  int    // 分段偏移量 13bit
	TTL      int    // 生命周期 4bit
	Protocol int    // 上层服务协议4bit
	Checksum int    // 头部校验和16bit
	Src      net.IP // 源IP  	32bit
	Dst      net.IP // 目的IP  	32bit
	Options  []byte // 选项, extension headers
}
// 

// Marshal encode ipv4 header
func (h *ipv4Header) Marshal() ([]byte, error) {
	if h == nil {
		return nil, syscall.EINVAL
	}

	hdrlen := ipv4HeaderLen + len(h.Options)
	b := make([]byte, hdrlen)

	//版本和头部长度
	b[0] = byte(ipv4Version<<4 | (hdrlen >> 2 & 0x0f))
	b[1] = byte(h.TOS)

	binary.BigEndian.PutUint16(b[2:4], uint16(h.TotalLen))
	binary.BigEndian.PutUint16(b[4:6], uint16(h.ID))

	flagsAndFragOff := (h.FragOff & 0x1fff) | int(h.Flags<<13)
	binary.BigEndian.PutUint16(b[6:8], uint16(flagsAndFragOff))

	b[8] = byte(h.TTL)
	b[9] = byte(h.Protocol)

	binary.BigEndian.PutUint16(b[10:12], uint16(h.Checksum))

	if ip := h.Src.To4(); ip != nil {
		copy(b[12:16], ip[:net.IPv4len])
	}

	if ip := h.Dst.To4(); ip != nil {
		copy(b[16:20], ip[:net.IPv4len])
	} else {
		return nil, errors.New("missing address")
	}

	if len(h.Options) > 0 {
		copy(b[ipv4HeaderLen:], h.Options)
	}

	return b, nil
}
