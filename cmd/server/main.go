package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/pelletier/go-toml/v2"

	"github.com/For-ACGN/Accelerator"
)

var cfgPath string

func init() {
	flag.StringVar(&cfgPath, "c", "config.toml", "configuration file path")
	flag.Parse()
}

func main() {
	cfgData, err := os.ReadFile(cfgPath)
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
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
