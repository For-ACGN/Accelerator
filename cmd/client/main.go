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
	"sync"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/For-ACGN/Accelerator"
)

var (
	cfgPath   string
	password  string
	pprofAddr string
)

func init() {
	flag.StringVar(&cfgPath, "config", "config.toml", "configuration file path")
	flag.StringVar(&password, "gen-hash", "", "generate password hash")
	flag.StringVar(&pprofAddr, "pprof-addr", "", "start pprof web server")
	flag.Parse()
}

func main() {
	if password != "" {
		hash := accelerator.GeneratePasswordHash([]byte(password))
		fmt.Println("password hash:", hash)
		return
	}
	if pprofAddr != "" {
		runPPROF()
	}

	cfgData, err := os.ReadFile(cfgPath) // #nosec
	checkError(err)
	decoder := toml.NewDecoder(bytes.NewReader(cfgData))
	decoder.DisallowUnknownFields()

	var config accelerator.ClientConfig
	err = decoder.Decode(&config)
	checkError(err)

	client, err := accelerator.NewClient(&config)
	checkError(err)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		// stop signal
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, os.Interrupt)
		<-signalCh

		err := client.Close()
		checkError(err)
	}()

	err = client.Run()
	checkError(err)

	wg.Wait()
}

func runPPROF() {
	listener, err := net.Listen("tcp", pprofAddr)
	checkError(err)

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

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
