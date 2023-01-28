package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/pelletier/go-toml/v2"

	"github.com/For-ACGN/Accelerator"
)

var (
	cfgPath   string
	password  string
	listDev   bool
	pprofAddr string
	pprofURL  string
)

func init() {
	flag.StringVar(&cfgPath, "config", "config.toml", "configuration file path")
	flag.StringVar(&password, "gen-hash", "", "generate password hash")
	flag.BoolVar(&listDev, "list-dev", false, "list network interface")
	flag.StringVar(&pprofAddr, "pprof-addr", "", "start pprof web server")
	flag.StringVar(&pprofURL, "pprof-url", "", "pprof web server url")
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
	if pprofAddr != "" {
		runPPROF()
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

	// stop signal
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	<-signalCh

	err = server.Close()
	if err != nil {
		log.Println("appear error when close server:", err)
	}
}

func listDevices() {
	devs, err := pcap.FindAllDevs()
	checkError(err)
	// sort device list by name
	sort.Slice(devs, func(i, j int) bool {
		return devs[i].Name < devs[j].Name
	})
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
			if !dev.Addresses[j].IP.IsGlobalUnicast() {
				continue
			}
			buf.WriteString(dev.Addresses[j].IP.String())
			if j != l-1 {
				buf.WriteString(" ")
			}
		}
		// for \\Device\\NPF_{GUID} on Windows
		dev.Name = strings.ReplaceAll(dev.Name, "\\", "\\\\")
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

func runPPROF() {
	listener, err := net.Listen("tcp", pprofAddr)
	checkError(err)

	if pprofURL != "" {
		if pprofURL[0] != '/' {
			pprofURL = "/" + pprofURL
		}
		last := len(pprofURL) - 1
		if pprofURL[last] == '/' {
			pprofURL = pprofURL[:last]
		}
	} else {
		pprofURL = fmt.Sprintf("/%d", time.Now().UnixNano())
	}
	log.Printf("[debug] pprof url: http://%s%s/debug/pprof/", listener.Addr(), pprofURL)

	pprofIndex := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, pprofURL+"/debug/pprof/") {
			name := strings.TrimPrefix(r.URL.Path, pprofURL+"/debug/pprof/")
			if name != "" {
				pprof.Handler(name).ServeHTTP(w, r)
				return
			}
		}
		pprof.Index(w, r)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(pprofURL+"/debug/pprof/", pprofIndex)
	mux.HandleFunc(pprofURL+"/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc(pprofURL+"/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc(pprofURL+"/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc(pprofURL+"/debug/pprof/trace", pprof.Trace)

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	go func() { _ = server.Serve(listener) }()
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
