package main

import (
	"net"
)

const (
	Version   = 6  // protocol version
	HeaderLen = 40 // header length
)

// A Header represents an IPv6 base header.
type IPV6Header struct {
	Version      int    // protocol version
	TrafficClass int    // traffic class
	FlowLabel    int    // flow label
	PayloadLen   int    // payload length
	NextHeader   int    // next header
	HopLimit     int    // hop limit
	Src          net.IP // source address
	Dst          net.IP // destination address
}

func (h *IPV6Header) Marshal() ([]byte, error) {
	return nil, nil
}
