package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/pelletier/go-toml/v2"

	"github.com/For-ACGN/Accelerator"
)

var (
	cfgPath  string
	password string
)

func init() {
	flag.StringVar(&cfgPath, "config", "config.toml", "configuration file path")
	flag.StringVar(&password, "gen-hash", "", "generate password hash")
	flag.Parse()
}

func main() {
	if password != "" {
		hash := accelerator.GeneratePasswordHash([]byte(password))
		fmt.Println("password hash:", hash)
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
