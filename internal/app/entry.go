package app

import (
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	cfg "candygo/internal/config"
)

func Main() {
	initThirdPartyLogger()

	if len(os.Args) > 1 && os.Args[1] == "service" {
		os.Exit(runService(os.Args[2:]))
	}

	args := cfg.NewArguments()
	if args.Parse(os.Args[1:]) != 0 {
		os.Exit(1)
	}
	if args.InitConfig {
		return
	}
	config := args.JSON()

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
					_ = cfg.SaveTunAddress(jsonString(config, "name", ""), addr)
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
