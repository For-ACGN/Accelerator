package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"

	"github.com/google/gopacket/pcap"
	"github.com/pelletier/go-toml/v2"

	"github.com/For-ACGN/Accelerator"
)

var (
	cfgPath  string
	password string
	listDev  bool
)

func init() {
	flag.StringVar(&cfgPath, "config", "config.toml", "configuration file path")
	flag.StringVar(&password, "gen-hash", "", "generate password hash")
	flag.BoolVar(&listDev, "list-dev", false, "list network interface")
	flag.Parse()
}

func main() {
	if password != "" {
		hash := accelerator.GeneratePasswordHash([]byte(password))
		fmt.Println("password hash:", hash)
		return
	}
	if listDev {
		listDevices()
		return
	}

	cfgData, err := os.ReadFile(cfgPath) // #nosec
	checkError(err)
	decoder := toml.NewDecoder(bytes.NewReader(cfgData))
	decoder.DisallowUnknownFields()

	var config accelerator.ServerConfig
	err = decoder.Decode(&config)
	checkError(err)

	server, err := accelerator.NewServer(&config)
	checkError(err)
	server.Run()

	go func() {
		_ = http.ListenAndServe("0.0.0.0:2080", nil)
	}()

	// stop signal
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	<-signalCh

	err = server.Close()
	checkError(err)
}

func listDevices() {
	devs, err := pcap.FindAllDevs()
	checkError(err)
	type item struct {
		name string
		ip   string
	}
	var (
		maxNameLen int
		items      []*item
	)
	buf := bytes.NewBuffer(make([]byte, 0, 64))
	for i := 0; i < len(devs); i++ {
		dev := devs[i]
		l := len(dev.Addresses)
		for j := 0; j < l; j++ {
			buf.WriteString(dev.Addresses[j].IP.String())
			if j != l-1 {
				buf.WriteString(", ")
			}
		}
		l = len(dev.Name)
		if l > maxNameLen {
			maxNameLen = l
		}
		items = append(items, &item{
			name: dev.Name,
			ip:   buf.String(),
		})
		buf.Reset()
	}
	format := fmt.Sprintf("%%-%ds  %%s\n", maxNameLen)
	fmt.Printf(format, "[Device Name]", "[IP Address]")
	for i := 0; i < len(items); i++ {
		fmt.Printf(format, items[i].name, items[i].ip)
	}
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
