// Brutter picks faster UDP source ports for CS and Valorant on an OpenWrt router.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/demyaha/brutter/internal/app"
	"github.com/demyaha/brutter/internal/config"
	"github.com/demyaha/brutter/internal/web"
)

var version = "dev"

func main() {
	path := flag.String("config", config.DefaultPath, "configuration file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	log.SetFlags(0)
	cfg, err := config.Load(*path)
	if err != nil {
		log.Fatal(err)
	}
	// At boot the WAN (PPPoE especially) may come up after Brutter starts.
	var logged time.Time
	for {
		err := cfg.Resolve()
		if err == nil {
			break
		}
		if time.Since(logged) >= time.Minute {
			log.Printf("waiting for the network: %v", err)
			logged = time.Now()
		}
		time.Sleep(5 * time.Second)
	}
	for _, dir := range []string{cfg.StateDir, cfg.RAMDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			log.Fatal(err)
		}
	}
	a := app.New(cfg)
	if err := a.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}
	server := &web.Server{App: a, Version: version}
	srv, err := server.Listen(cfg.Listen, cfg.Port)
	if err != nil {
		a.Stop()
		log.Fatalf("listen: %v", err)
	}
	log.Printf("brutter %s: http://%s:%d/ (LAN %s, WAN %s)", version, cfg.Listen, cfg.Port, cfg.LAN, cfg.WAN)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	a.Stop()
}
