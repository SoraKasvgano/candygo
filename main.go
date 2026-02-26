package main

import (
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	initThirdPartyLogger()

	if len(os.Args) > 1 && os.Args[1] == "service" {
		os.Exit(runService(os.Args[2:]))
	}

	args := arguments{
		mtu: 1400,
	}
	if args.parse(os.Args[1:]) != 0 {
		os.Exit(1)
	}
	if args.initConfig {
		return
	}
	config := args.json()

	mode := jsonString(config, "mode", "")
	if mode == "client" {
		id := "cli"
		hookSignal(func() {
			_ = client.shutdown(id)
		})

		go func() {
			for {
				time.Sleep(time.Second)
				status, ok := client.status(id)
				if !ok {
					continue
				}
				addr := jsonString(status, "address", "")
				if strings.TrimSpace(addr) != "" {
					_ = saveTunAddress(jsonString(config, "name", ""), addr)
					break
				}
			}
		}()

		_ = client.run(id, config)
		return
	}

	if mode == "server" {
		hookSignal(func() {
			_ = server.shutdown()
		})
		_ = server.run(config)
		return
	}

	os.Exit(1)
}

func hookSignal(fn func()) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fn()
	}()
}
