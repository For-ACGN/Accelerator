package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"
)

var (
	localAddr  string
	remoteAddr string
)

func init() {
	flag.StringVar(&localAddr, "l", "0.0.0.0:0", "local address")
	flag.StringVar(&remoteAddr, "r", "127.0.0.1:3080", "server address")
	flag.Parse()
}

func main() {
	lAddr, err := net.ResolveUDPAddr("udp", localAddr)
	checkError(err)
	rAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	checkError(err)
	pc, err := net.ListenUDP("udp", lAddr)
	checkError(err)
	buf := make([]byte, 64)
	_, _ = pc.WriteTo(buf, rAddr)
	for {
		_, addr, err := pc.ReadFrom(buf)
		checkError(err)
		fmt.Println(time.Now().Format(time.RFC3339), addr)
	}
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
