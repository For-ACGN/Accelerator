package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"
)

var address string

func init() {
	flag.StringVar(&address, "addr", "0.0.0.0:3080", "server address")
	flag.Parse()
}

func main() {
	pc, err := net.ListenPacket("udp", address)
	checkError(err)
	buf := make([]byte, 64)
	for {
		_, addr, err := pc.ReadFrom(buf)
		checkError(err)
		go func(addr net.Addr) {
			fmt.Println(time.Now().Format(time.RFC3339), addr)
			for i := 0; i < 60*240; i++ {
				_, _ = pc.WriteTo(buf, addr)
				time.Sleep(time.Second / 60)
			}
		}(addr)
	}
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
