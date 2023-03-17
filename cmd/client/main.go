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
	"strings"
	"sync"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/For-ACGN/Accelerator"
)

var (
	cfgPath   string
	password  string
	pprofAddr string
	pprofURL  string
)

func init() {
	flag.StringVar(&cfgPath, "config", "config.toml", "configuration file path")
	flag.StringVar(&password, "gen-hash", "", "generate password hash")
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
		if err != nil {
			log.Println("appear error when close client:", err)
		}
	}()

	err = client.Run()
	checkError(err)

	wg.Wait()
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
	log.Printf("[info] pprof url: http://%s%s/debug/pprof/", listener.Addr(), pprofURL)

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
